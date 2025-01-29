# Standard Agent development workflow

## Requirements

Install the `deva` tool, as explained in the [setup page](setup.md#tooling).

## Local development

### How to test changes

#### Go code changes

To run go linters:

=== "On your laptop"
    ```
    deva inv linter.go --only-modified-packages
    ```
=== "On Linux"
    ```
    deva inv linter.go --only-modified-packages --run-on linux
    ```

To run go copyrights linters:
```
deva inv linter.copyrights
```
<!--- Note(consistency): May catch test modules  --->


To run go unit tests:

=== "On your laptop"
    ```
    deva inv test --only-impacted-packages
    ```
=== "On Linux"
    ```
    deva inv test --only-impacted-packages --run-on linux
    ```
<!--- Note(consistency): Why does linter.go not support --only-impacted-packages? --->

#### Go dependencies changes

To verify that `go.mod` and `go.sum` files are up-to-date:
```
deva inv check-mod-tidy
```

To update `go.mod` and `go.sum` files across the repository:
```
deva inv tidy
```

#### Go modules changes

To verify that go modules are properly declared:
```
deva inv modules.validate --fix-format
```

#### Protobuf changes

To update protobuf generated files:
```
deva inv protobuf.generate
```
<!--- Note(fixme): deva inv setup installs protoc in $HOME/.local/bin, which may not be in the PATH of users --->

#### Gitlab configuration changes

Note: Requires a valid `GITLAB_TOKEN` environment variable.

To verify Gitlab configuration files:

=== "Verify configuration on `main`"
    ```
    deva inv linter.gitlab-ci -t main
    ```
=== "Verify all configurations"
    ```
    deva inv linter.gitlab-ci
    ```

To verify `JOBOWNERS` configuration:

```
deva inv linter.gitlab-ci-jobs-codeowners
```
<!--- Note(consistency): this task skips lint if no relevant changes, the linter.gitlab-ci one does not --->

### How to build Agent binaries