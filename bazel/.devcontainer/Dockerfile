FROM registry.ddbuild.io/ci/datadog-agent-buildimages/linux-glibc-2-17-x64:v60428782-34a49350

RUN curl -LO https://github.com/bazelbuild/bazelisk/releases/download/v1.20.0/bazelisk-linux-arm64 \
    && chmod +x /bazelisk-linux-arm64 \
    && ln -s /bazelisk-linux-arm64 /usr/local/bin/bazel

# Make Bazel output stuff to a volume we're mounting
RUN echo "startup --output_user_root=/tmp/bazel/build_output" > /etc/bazel.bazelrc

# Run forever so that we can interact with the container via `docker exec`
ENTRYPOINT ["tail", "-f", "/dev/null"]
