# Dockerfile for the online double-signal leg of test/online_signals.sh
# (issue #45). The probe is baked in with file capabilities so an
# unprivileged container user can capture on the container's loopback -
# no host change and no --cap-add needed (which cannot raise a non-root
# user's bounding set anyway).
#
# Stage a build context and build the image:
#
#   ctx=$(mktemp -d)
#   cp probe "$ctx/"
#   mkdir -p "$ctx/libs"
#   # copy the shared libraries the binary needs (see `ldd probe`):
#   cp <mmt-base>/dpi/lib/libmmt_*.so* "$ctx/libs/"
#   cp <mmt-base>/security/lib/libmmt_*.so* "$ctx/libs/"   # SECURITY builds
#   cp -r <mmt-base>/plugins "$ctx/"
#   # SECURITY builds also need the engine tree; other builds stage an
#   # empty directory because COPY requires the path to exist:
#   mkdir "$ctx/security" && cp -r <mmt-base>/security/. "$ctx/security/"
#   cc -O2 -static -o "$ctx/udp_gen" test/double-signal/udp_gen.c
#   cp test/double-signal/inner_container.sh "$ctx/"
#   docker build -f test/double-signal/Dockerfile -t i45-probe "$ctx"
#
# then run the leg:
#   NET_RAW_IMAGE=i45-probe sh test/online_signals.sh
FROM ubuntu:24.04

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libpcap0.8 libcap2-bin libconfuse2 libxml2 libuuid1 util-linux \
 && rm -rf /var/lib/apt/lists/*

COPY probe /opt/mmt/probe/probe
COPY libs/ /opt/mmt/lib/
COPY plugins/ /opt/mmt/plugins/
#present only when the build has SECURITY_MODULE: the engine's rules and
# default configuration are read at the hardcoded /opt/mmt/security path
COPY security/ /opt/mmt/security/
COPY udp_gen /usr/local/bin/udp_gen
COPY inner_container.sh /opt/inner_container.sh

#the probe's file capabilities make its exec a secure-execution one, so
# LD_LIBRARY_PATH is ignored: register the library folder with ldconfig
# instead. cap_net_admin is intentionally not given - it is outside
# docker's default bounding set, so a binary asking for it would not even
# exec
RUN echo /opt/mmt/lib > /etc/ld.so.conf.d/mmt.conf && ldconfig \
 && setcap 'cap_net_raw+eip' /opt/mmt/probe/probe
