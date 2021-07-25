#! /bin/bash

counter=0
for filename in ../../../emails//*.eml; do
    [ -e "$filename" ] || continue
    echo "$filename"
    echo -n "dkimverify: "
    cat "$filename" | python3 ../../dkimpy/dkim/dkimverify.py
    echo -n "mailauth: "
    cat "$filename" | mailauth report | jq .dkim.results[0].info
    echo -n "dkimverifier: "
    swift run DKIMVerifierTool "$filename" 2>1
    echo "----------------"
    ((counter++))
    if [ $counter -eq 25 ]
    then
      break
    fi
done


# cat filesnames.txt | gxargs -d'\n' -t -n1 sh -c 'cat "$0" | mailauth report | jq .dkim.results[0].info' &> dkim_report_mailauth.txt
# #gfind ../../../emails/ -name "*.eml" -type f -exec sh -c 'echo "$1";cat "$1" | python3 ../dkimpy/dkim/dkimverify.py' sh {} \; &> dkim_report_dkimpy.txt
# gfind ../../../emails/ -name "*.eml" -type f | head -n 10 | gxargs -d'\n' -t -n1 sh -c 'cat "$0" | python3 ../../dkimpy/dkim/dkimverify.py'  &> dkim_report_dkimpy.txt
# #gfind ../../../emails/ -name "*.eml" -type f -exec sh -c 'echo "$1"; swift run DKIMVerifierTool "$1"' sh {} \; &> dkim_report_dkimverifier.txt
# gfind ../../../emails/ -name "*.eml" -type f | head -n 10 | gxargs -d'\n' -t -n1 sh -c 'swift run DKIMVerifierTool "$0"'  &> dkim_report_dkimverifier.txt