#!/bin/bash

input_file=$1

awk -F ',' '
{
    lines[NR] = $0
    if ($1 == "DOMAIN-SUFFIX") {
        suffix_set[$2] = 1
    }
}
END {
    for (i = 1; i <= NR; i++) {
        line = lines[i]
        if (line ~ /^DOMAIN-SUFFIX,/) {
            print line
        } else if (line ~ /^DOMAIN,/) {
            split(line, parts, /,/)
            domain = parts[2]
            n = split(domain, arr, ".")
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
' "$input_file"
