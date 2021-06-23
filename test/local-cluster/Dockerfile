# We are going with Hot Pocket NodeJs docker image because sample contracts need NodeJs to run.
FROM hotpocketdev/hotpocket:ubt.20.04-njs.14

COPY hpcore hpfs hpws appbill /usr/local/bin/hotpocket/

ENTRYPOINT ["/usr/local/bin/hotpocket/hpcore"]

# Run with valgrind
# ENTRYPOINT ["valgrind", "/hp/hpcore"]