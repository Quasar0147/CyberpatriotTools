apt-get install libopenscap8
DICT="./Canonical_Ubuntu_20.04_Benchmarks-cpe-dictionary.xml"
XMLPATH="./Canonical_Ubuntu_20.04_Benchmarks-xccdf.xml"
oscap info $XMLPATH
read -p 'What Profile: ' PROFILE
oscap xccdf eval --remediate --profile $PROFILE --cpe $DICT $XMLPATH
