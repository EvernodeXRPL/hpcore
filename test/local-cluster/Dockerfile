# We are going with Hot Pocket NodeJs docker image because sample contracts need NodeJs to run.
FROM evernodedev/hotpocket:0.6-ubt.20.04-njs.16

COPY hpcore hpfs hpws /usr/local/bin/hotpocket/

ENTRYPOINT ["/usr/local/bin/hotpocket/hpcore"]

# Run with valgrind

# RUN apt-get install --no-install-recommends -y gdb valgrind
# ENTRYPOINT ["valgrind", "/usr/local/bin/hotpocket/hpcore"]