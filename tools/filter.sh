#!/bin/bash

input_file="$1"

awk -F ',' '
{
    lines[NR] = $0
    type = $1
    value = $2

    if (type == "DOMAIN-SUFFIX") {
        suffix_set[value] = 1
    }
}
END {
    for (i = 1; i <= NR; i++) {
        line = lines[i]
        split(line, parts, /,/)
        type = parts[1]
        value = parts[2]

        if (type == "DOMAIN-SUFFIX") {
            print line
        } else if (type == "DOMAIN") {
            # Check if domain is already covered by DOMAIN-SUFFIX
            n = split(value, arr, ".")
            found = 0
            for (j = 1; j <= n; j++) {
                parent = arr[j]
                for (k = j + 1; k <= n; k++) {
                    parent = parent "." arr[k]
                }
                if (parent in suffix_set) {
                    found = 1
                    break
                }
            }
            if (!found) print line
        } else {
            print line
        }
    }
}
' "$input_file" | sort -fu
