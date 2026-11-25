/*
 * mqtt_output.c
 *
 *  Created on: May 7, 2025
 *      Author: nhnghia
 */

#include <MQTTClient.h>
#include <time.h>
#include "mqtt_output.h"
#include "../../../lib/log.h"
#include "../../../lib/malloc.h"

//a dead channel retries the broker no faster than this interval, so a
// connect that blocks up to the connect timeout cannot stall the output
// worker for longer
#define MQTT_RECONNECT_INTERVAL_SECONDS  10
//reports dropped on a dead channel are counted and reported at most once
// per this interval
#define MQTT_DROP_LOG_INTERVAL_SECONDS   30

struct mqtt_output_struct{
	uint16_t probe_id;
	const mqtt_output_conf_t *config;
	MQTTClient client;
	time_t last_connect_attempt;
	time_t last_drop_log;
	uint64_t dropped_reports;
};

static void _connect_to_mqtt(mqtt_output_t *context) {
	//an already-open client must not be created a second time
	if( context->client != NULL )
		return;

	char client_id[100];
	snprintf(client_id, sizeof(client_id), "mmt-probe-%d", context->probe_id);

	MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;

	conn_opts.keepAliveInterval = 20;
	conn_opts.cleansession = 1;
	conn_opts.connectTimeout = 5;

	context->last_connect_attempt = time( NULL );

	int rc;

	rc = MQTTClient_create(&context->client, context->config->address,
			client_id, MQTTCLIENT_PERSISTENCE_NONE, NULL);

	if( rc ){
		log_write( LOG_ERR, "Failed to create MQTT client '%s: %d'", client_id, rc);
		context->client = NULL;
		return;
	} else
		log_write( LOG_INFO, "Created MQTT client '%s'", client_id);


	rc = MQTTClient_connect(context->client, &conn_opts);
	if( rc != MQTTCLIENT_SUCCESS ) {
		//an unreachable broker disables this channel but must not kill the
		// probe: other channels - and the output itself - keep working
		log_write(LOG_ERR, "Failed to connect MQTT to '%s': %d", context->config->address, rc);
		MQTTClient_destroy(&context->client);
		context->client = NULL;
	} else
		log_write(LOG_INFO, "Connected MQTT to '%s'", context->config->address);
}

mqtt_output_t* mqtt_output_alloc_init( const mqtt_output_conf_t*config,  uint16_t probe_id ){
	if( config->is_enable == false)
		return NULL;
	mqtt_output_t *ret = mmt_alloc_and_init_zero( sizeof( mqtt_output_t ));
	ret->probe_id = probe_id;
	ret->config = config;

	//trigger the connection
	_connect_to_mqtt( ret );

	return ret;
}

int mqtt_output_send( mqtt_output_t *context, const char *message ){
	if( context == NULL )
		return 0;

	//the channel is down (an unreachable broker at start-up, or a lost
	// connection): count the dropped report, warn at most once per
	// MQTT_DROP_LOG_INTERVAL_SECONDS, and retry the connect every
	// MQTT_RECONNECT_INTERVAL_SECONDS so a late broker is picked up
	if( context->client == NULL ){
		context->dropped_reports ++;
		const time_t now = time( NULL );
		if( now - context->last_drop_log >= MQTT_DROP_LOG_INTERVAL_SECONDS ){
			log_write( LOG_WARNING, "MQTT channel to '%s' is down: dropped %llu report(s)",
					context->config->address, (unsigned long long) context->dropped_reports );
			context->last_drop_log    = now;
			context->dropped_reports  = 0;
		}
		if( now - context->last_connect_attempt >= MQTT_RECONNECT_INTERVAL_SECONDS )
			_connect_to_mqtt( context );
		return 0;
	}
	MQTTClient_message pubmsg = MQTTClient_message_initializer;
	MQTTClient_deliveryToken token;
	int rc;

	pubmsg.payload = (void *)message;
	pubmsg.payloadlen = (int) strlen(message);
	pubmsg.qos = 2; //Once and one only - the message will be delivered exactly once.
	pubmsg.retained = context->config->is_retain;

	rc = MQTTClient_publishMessage(context->client, context->config->topic_name, &pubmsg, &token);
	if( rc != MQTTCLIENT_SUCCESS ){
		//a failed publish drops the report: count it and log at most once
		// per MQTT_DROP_LOG_INTERVAL_SECONDS, like the dead-channel path
		context->dropped_reports ++;
		const time_t now = time( NULL );
		if( now - context->last_drop_log >= MQTT_DROP_LOG_INTERVAL_SECONDS ){
			log_write( LOG_ERR, "Failed to publish MQTT message to '%s': %d (dropped %llu report(s))",
					context->config->topic_name, rc, (unsigned long long) context->dropped_reports );
			context->last_drop_log   = now;
			context->dropped_reports = 0;
		}
		//a dead connection goes through the same drop/reconnect path as a
		// never-opened one
		if( rc == MQTTCLIENT_DISCONNECTED )
			MQTTClient_destroy( &context->client );
		return 0;
	}

	const unsigned long timeout = 10*1000; //The maximum time to wait in milliseconds.
	//wait for the message has been published
	rc = MQTTClient_waitForCompletion(context->client, token, timeout);
	return 1;
}

void mqtt_output_flush( mqtt_output_t * context){

}

void mqtt_output_release( mqtt_output_t * context){
	if( context == NULL )
		return;

	if( context->client != NULL ){
		int rc = MQTTClient_disconnect(context->client, 10000);

		if( rc != MQTTCLIENT_SUCCESS)
			log_write(LOG_ERR, "Failed to disconnect MQTT client: %d", rc);

		MQTTClient_destroy(&context->client);
	}
	mmt_probe_free( context );
}
