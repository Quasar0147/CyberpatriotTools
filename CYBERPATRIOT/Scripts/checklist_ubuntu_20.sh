e() {
    for x in "$@"
    do
        for y in $(find $x -type f)
        do
            nano $y
        done
    done
}
e /etc/apt
rm -r /etc/bash_completion.d
