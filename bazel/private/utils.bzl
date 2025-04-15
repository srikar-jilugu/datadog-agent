def expand_header_deps(header_deps):
    """
    Expand a header only cc_library dependency to:
      * a list of dependant files that can be provided to a depset as
        transitive rule depencency and as actions inputs
      * a list of "-I ..." compiler flags pointing at the headers directory.
    """
    _ccinfo_deps = [dep[CcInfo] for dep in header_deps]
    # Temporary set to ensure we're not passing the same "-I folder" 15 times
    header_dirs = set([
        h.dirname
        for d in _ccinfo_deps
            for h in d.compilation_context.direct_headers
    ])
    deps = [h for d in _ccinfo_deps for h in d.compilation_context.direct_headers]
    return deps, list(header_dirs)
