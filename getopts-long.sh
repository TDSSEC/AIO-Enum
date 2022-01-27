# Taken from https://gist.github.com/nicowilliams/f3fe2b10b380aecdef403acb246dced2
# getopts_long long_opts_assoc_array_name optstring optname args...
#
#   long_opts_assoc_array_name is the name of an associative array whose
#   indices are long option names and whose values are either the empty
#   string (option takes no argument) or : (option takes an argument).
#
#   optstring is an optstring value for getopts
#
#   optname is the name of a variable in which to put the matched option
#   name / letter.
#
#   args... is the arguments to parse.
#
# As with getopts, $OPTIND is set to the next argument to check at the
# next invocation.  Unset OPTIND or set it to 1 to reset options
# processing.
#
# As with getopts, "--" is a special argument that ends options
# processing.
#
function getopts_long {
    if (($# < 3)); then
        printf 'bash: illegal use of getopts_long\n'
        printf 'Usage: getopts_long lvar optstring name [ARGS]\n'
        printf '\t{lvar} is the name of an associative array variable\n'
        printf '\twhose keys are long option names and values are\n'
        printf '\tthe empty string (no argument) or ":" (argument\n'
        printf '\trequired).\n\n'
        printf '\t{optstring} and {name} are as for the {getopts}\n'
        printf '\tbash builtin.\n'
        return 1
    fi 1>&2
    [[ ${1:-} != largs ]] && local -n largs="$1"
    local optstr="$2"
    [[ ${3:-} != opt ]] && local -n opt="$3"
    local optvar="$3"
    shift 3

    OPTARG=
    : "${OPTIND:=1}"
    opt=${@:$OPTIND:1}
    if [[ $opt = -- ]]; then
        opt='?'
        return 1
    fi
    if [[ $opt = --* ]]; then
        local optval=false
        opt=${opt#--}
        if [[ $opt = *=* ]]; then
            OPTARG=${opt#*=}
            opt=${opt%%=*}
            optval=true
        fi
        ((++OPTIND))
        if [[ ${largs[$opt]+yes} != yes ]]; then
            ((OPTERR)) && printf 'bash: illegal long option %s\n' "$opt" 1>&2
            return 0
        fi
        if [[ ${largs[$opt]:-} = : ]]; then
            if ! $optval; then
                OPTARG=${@:$OPTIND:1}
                ((++OPTIND))
            fi
        fi
        return 0
    fi
    getopts "$optstr" "$optvar" "$@"
}