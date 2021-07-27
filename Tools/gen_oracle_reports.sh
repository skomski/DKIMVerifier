#! /bin/bash

# Usage: ./Tools/gen_oracle_reports.sh ../../emails 50 > oracle_log.csv

swift build | true

echo "filename,dkimpy,mailauth,dkimverifier"

emails_location=$1
count_emails=$2

counter=0
for filename in $emails_location/*.eml; do
    [ -e "$filename" ] || continue
    printf "$filename" | sed -e 's/"/""/g' | xargs -0 -I{} printf "\"{}\","
    cat "$filename" | dkimverify 2>&1 | sed '$!d' | tr -d '\n' | sed -e 's/"/""/g' | xargs -0 -I{} printf "\"{}\""
    printf ","
    cat "$filename" | mailauth report | jq .dkim.results[0].info | tr -d '\n' | sed 's:^.\(.*\).$:\1:' | sed -e 's/"/""/g' | xargs -0 -I{} printf "\"{}\""
    printf ","
    swift run --skip-build DKIMVerifierTool "$filename" | tr -d '\n' | sed -e 's/"/""/g' | xargs -0 -I{} printf "\"{}\""
    echo ""
    ((counter++))
    if [ $counter -eq $count_emails ]
    then
      break
    fi
done
