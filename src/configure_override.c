/*
 * configure_override.c
 *
 *  Created on: Apr 23, 2018
 *          by: Huu Nghia Nguyen
 */

#include "lib/log.h"
#include "lib/malloc.h"
#include "lib/memory.h"

#include "configure_override.h"

static bool _parse_bool( const char *value ){
	if( IS_EQUAL_STRINGS( value, "true" ) )
		return true;
	if( IS_EQUAL_STRINGS( value, "false" ) )
		return false;
	return false;
}

const identity_t* conf_get_identity_from_string( const char * ident_str ){
	const identity_t *identities;
	size_t nb_parameters = conf_get_identities( &identities );
	int i;
	for( i=0; i<nb_parameters; i++ )
		if( IS_EQUAL_STRINGS( ident_str, identities[i].ident ))
			return &identities[i];
	return NULL;
}


/*
 * The enum-like parameters: their value is a name, parsed by the same
 * function as the configuration file, so -X accepts exactly the values the
 * file accepts. 'values' is that parser's list of accepted names.
 */
typedef struct {
	int ident;
	bool (*parse)( int *result, const char *value );
	const char *values;
} enum_parameter_t;

static const enum_parameter_t* _get_enum_parameter( int ident_val ){
	static const enum_parameter_t enums[] = {
		{ CONF_ATT__INPUT__MODE,              conf_parse_input_mode,           CONF_INPUT_MODE_VALUES },
		{ CONF_ATT__SESSION_REPORT__RTT_BASE, conf_parse_rtt_base,             CONF_RTT_BASE_VALUES },
		{ CONF_ATT__OUTPUT__FORMAT,           conf_parse_output_format,        CONF_OUTPUT_FORMAT_VALUES },
#ifdef SOCKET_MODULE
		{ CONF_ATT__SOCKET_OUTPUT__TYPE,      conf_parse_output_socket_type,   CONF_SOCKET_TYPE_VALUES },
#endif
#ifdef SECURITY_MODULE
		{ CONF_ATT__SECURITY__INGORE_REMAIN_FLOW, conf_parse_security_ignore_mode, CONF_SECURITY_IGNORE_REMAIN_FLOW_VALUES },
#endif
	};
	size_t i;
	for( i=0; i<sizeof( enums ) / sizeof( enums[0] ); i++ )
		if( enums[i].ident == ident_val )
			return &enums[i];
	return NULL;
}

const char* conf_validate_data_value( const identity_t *ident, const char *data_value ){
	static char error_reason[1000];
	int i;
	int enum_val = 0;
	uint32_t u32_val;

	//an enum-like parameter takes a name, not the number of its storage
	// type: its parser accepts exactly the values the configuration file
	// does - checked before the storage type below
	const enum_parameter_t *enum_param = _get_enum_parameter( ident->val );
	if( enum_param != NULL ){
		if( enum_param->parse( &enum_val, data_value ) )
			return NULL;
		snprintf( error_reason, sizeof( error_reason),
				"Unexpected value [%s] for [%s]: expect %s",
				data_value, ident->ident, enum_param->values );
		return error_reason;
	}

	//special data type
	switch( ident->val ){
	case CONF_ATT__INPUT__SNAP_LEN:
#ifdef PCAP_DUMP_MODULE
	case CONF_ATT__DUMP_PCAP__SNAP_LEN:
#endif
		if( conf_parse_snap_len( &u32_val, data_value ) )
			return NULL;
		snprintf( error_reason, sizeof( error_reason),
				"Expect a number from 0 to %d as value of '%s' (not '%s')",
				PCAP_FILE_SNAP_LEN_MAX, ident->ident, data_value );
		return error_reason;
	default:
		break;
	}

	//check value depending on data type of parameter
	switch( ident->data_type ){
	case BOOL:
		if( IS_EQUAL_STRINGS( data_value, "true" ) )
			break;
		if( IS_EQUAL_STRINGS( data_value, "false" ) )
			break;

		snprintf( error_reason, sizeof(error_reason), "Expect either 'true' or 'false' as value of '%s' (not '%s')", ident->ident, data_value );
		return error_reason;
		break;

	case UINT16_T:
	case UINT32_T:
		//check if data_value contains only the number
		i = 0;
		while( data_value[i] != '\0' ){
			if( data_value[i] < '0' || data_value[i] > '9' ){
				snprintf( error_reason, sizeof( error_reason), "Expect a number as value of '%s' (not '%s')", ident->ident, data_value );
				return error_reason;
			}
			i ++;
		}
		break;
	default:
		break;
	}

	return NULL;
}

//The titled 'reconstruct-data' blocks are CFGF_MULTI: a block left out of the
// configuration file leaves its pointer NULL, so it has no field to override.
static inline bool _is_block_missing( const probe_conf_t *conf, const identity_t *ident ){
	const char *block = NULL;
	switch( ident->val ){
#ifdef FTP_RECONSTRUCT_MODULE
	case CONF_ATT__RECONSTRUCT_DATA__FTP__ENABLE:
	case CONF_ATT__RECONSTRUCT_DATA__FTP__OUTPUT_DIR:
		if( conf->reconstructions.ftp == NULL )
			block = "reconstruct-data ftp";
		break;
#endif
#ifdef HTTP_RECONSTRUCT_MODULE
	case CONF_ATT__RECONSTRUCT_DATA__HTTP__ENABLE:
	case CONF_ATT__RECONSTRUCT_DATA__HTTP__OUTPUT_DIR:
		if( conf->reconstructions.http == NULL )
			block = "reconstruct-data http";
		break;
#endif
	default:
		break;
	}
	if( block == NULL )
		return false;
	log_write( LOG_ERR, "Cannot set [%s]: the configuration has no '%s' block", ident->ident, block );
	return true;
}

static inline conf_override_ret_t _override_element_by_ident( probe_conf_t *conf, const identity_t *ident, const char *value_str ){
	uint32_t int_val = 0;
	int i;
	DEBUG("Updating %s to %s", ident->ident, value_str );
	if( _is_block_missing( conf, ident ) )
		return CONF_OVERRIDE__NO_BLOCK;
	void *field_ptr = conf_get_ident_attribute_field(conf, ident->val );
	int enum_val = 0;

	if( field_ptr == NULL ){
		log_write( LOG_WARNING, "Have not supported yet for [%s]", ident->ident );
		return CONF_OVERRIDE__REFUSED;
	}
	char **string_ptr;

	//enum-like parameters: parsed as in the configuration file
	const enum_parameter_t *enum_param = _get_enum_parameter( ident->val );
	if( enum_param != NULL ){
		if( ! enum_param->parse( &enum_val, value_str ) ){
			log_write( LOG_WARNING, "Unexpected value [%s] for [%s]: expect %s",
					value_str, ident->ident, enum_param->values );
			return CONF_OVERRIDE__REFUSED;
		}
		*((int *)field_ptr) = enum_val;
		return CONF_OVERRIDE__OK;
	}

	//special data type
	switch( ident->val ){
	//snap-len values are bounded by libpcap's maximum record size: a
	// non-numeric, negative or bigger value is rejected instead of being
	// silently wrapped into the field
	case CONF_ATT__INPUT__SNAP_LEN:
#ifdef PCAP_DUMP_MODULE
	case CONF_ATT__DUMP_PCAP__SNAP_LEN:
#endif
		if( ! conf_parse_snap_len( &int_val, value_str ) ){
			log_write( LOG_WARNING, "Unexpected value [%s] for [%s]: expect a number from 0 to %d",
					value_str, ident->ident, PCAP_FILE_SNAP_LEN_MAX );
			return CONF_OVERRIDE__REFUSED;
		}
		//value does not change ==> do nothing
		if( int_val == *((uint32_t *)field_ptr) )
			return CONF_OVERRIDE__OK;
		*((uint32_t *)field_ptr) = int_val;
		return CONF_OVERRIDE__OK;
	default:
		break;
	}

	switch( ident->data_type ){
	//update value depending on parameters
	case NO_SUPPORT:
		log_write( LOG_WARNING, "Have not supported yet for [%s]", ident->ident );
		return CONF_OVERRIDE__REFUSED;
	case CHAR_STAR:
		string_ptr = (char **) field_ptr;
		//value does not change ==> do nothing
		if( *string_ptr && IS_EQUAL_STRINGS( *string_ptr, value_str ) )
			return CONF_OVERRIDE__OK;
		mmt_probe_free( *string_ptr );
		*string_ptr = mmt_strdup( value_str );
		return CONF_OVERRIDE__OK;
	case LIST:
		switch( ident->val ){
#ifdef SECURITY_MODULE
		case CONF_ATT__SECURITY__OUTPUT_CHANNEL:
#endif
		case CONF_ATT__SESSION_REPORT__OUTPUT_CHANNEL:
		case CONF_ATT__SYSTEM_REPORT__OUTPUT_CHANNEL:
		case CONF_ATT__MICRO_FLOWS__OUTPUT_CHANNEL:
		case CONF_ATT__RADIUS_REPORT__OUTPUT_CHANNEL:
			int_val = conf_parse_output_channel( value_str );
			if( int_val == *(output_channel_conf_t *) field_ptr )
				return CONF_OVERRIDE__OK;
			(*(output_channel_conf_t *) field_ptr) = int_val;
			return CONF_OVERRIDE__OK;

#ifdef PCAP_DUMP_MODULE
		case CONF_ATT__DUMP_PCAP__PROTOCOLS:
			//free old memory
			if( conf->reports.pcap_dump ){
				if( conf->reports.pcap_dump->protocols != NULL ){
					for( i=0; i<conf->reports.pcap_dump->protocols_size; i++ )
						mmt_probe_free( conf->reports.pcap_dump->protocols[i] );
				}
				mmt_probe_free( conf->reports.pcap_dump->protocols );
			}else{
				conf->reports.pcap_dump = mmt_alloc_and_init_zero( sizeof( pcap_dump_conf_t ));
			}

			conf->reports.pcap_dump->protocols_size = conf_parse_list( value_str, &conf->reports.pcap_dump->protocols );
			return CONF_OVERRIDE__OK;
#endif
		}
		break;
	case BOOL:
		int_val = _parse_bool( value_str );
		//value does not change => do nothing
		if( int_val == *((bool *)field_ptr) )
			return CONF_OVERRIDE__OK;
		//update value
		*((bool *)field_ptr) = int_val;
		return CONF_OVERRIDE__OK;


	case UINT16_T:
		int_val = atoi( value_str );
		//value does not change ==> do nothing
		if( int_val == *((uint16_t *)field_ptr) )
			return CONF_OVERRIDE__OK;
		*((uint16_t *)field_ptr) = int_val;
		return CONF_OVERRIDE__OK;

	case UINT32_T:
		int_val = atol( value_str );
		//value does not change ==> do nothing
		if( int_val == *((uint32_t *)field_ptr) )
			return CONF_OVERRIDE__OK;
		*((uint32_t *)field_ptr) = int_val;
		return CONF_OVERRIDE__OK;
	default:
		break;
	}

	log_write( LOG_ERR, "Unknown identifier '%s'", ident->ident );
	return CONF_OVERRIDE__REFUSED;
}


/**
 * Update value of a configuration parameter.
 * The new value is updated only if it is different with the current value of the parameter.
 * @param conf
 * @param ident
 * @param value
 * @return 0 if the new value is updated, otherwise false
 */
int conf_override_element( probe_conf_t *conf, const char *ident_str, const char *value_str ){
	const identity_t *ident = conf_get_identity_from_string( ident_str );

	if( ident == NULL ){
		log_write( LOG_WARNING, "Unknown parameter identity [%s]", ident_str );
		return CONF_OVERRIDE__UNKNOWN_IDENT;
	}
	return _override_element_by_ident(conf, ident, value_str );
}

bool conf_override_element_by_id( probe_conf_t *conf, int ident_val, const char *value_str ){
	const identity_t *ident = conf_get_identity_from_id( ident_val );

	if( ident == NULL ){
		log_write( LOG_WARNING, "Unknown parameter identity [%d]", ident_val );
		return false;
	}
	return _override_element_by_ident(conf, ident, value_str ) == CONF_OVERRIDE__OK;
}


/**
 * Public API
 */
void conf_print_identities_list(){
	int i;
	const char *data_type_strings[] = {
			"",
			"boolean",
			"uint16_t",
			"uint32_t",
			"string",
			"string"
	};

	const identity_t *identities;
	size_t nb_parameters = conf_get_identities( &identities );

	const enum_parameter_t *enum_param;

	for( i=0; i<nb_parameters; i++ ){
		if( identities[i].data_type == NO_SUPPORT )
			continue;
		//an enum-like parameter takes a name, not the number of its storage type
		enum_param = _get_enum_parameter( identities[i].val );
		if( enum_param != NULL )
			printf("%s (%s)\n", identities[i].ident, enum_param->values );
		else
			printf("%s (%s)\n", identities[i].ident, data_type_strings[identities[i].data_type]);
	}
}
