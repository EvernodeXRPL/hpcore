# We are going with HotPocket NodeJs docker image because sample contracts need NodeJs to run.
FROM evernodedev/hotpocket:latest-ubt.20.04-njs.20

# Copy (overwrite) the local build outputs into the docker image.
COPY hpcore hpfs hpws debug_shell /usr/local/bin/hotpocket/

ENTRYPOINT ["/usr/local/bin/hotpocket/hpcore"]

# Run with valgrind

# RUN apt-get install --no-install-recommends -y gdb valgrind
# ENTRYPOINT ["valgrind", "/usr/local/bin/hotpocket/hpcore"]