cat << 'EOF' > outfile
                                         �ޖr�<���X���ю��YΛ(�cz�J��+���N�+��g݂��@���7ǎ������tX����۾7�%�[�@�\��&&��9�G�eV�>��xkl7�,�fR����U��c�x
EOF
sInFile=$(cat outfile | grep -c "YN")
[[ isInFile = 1 ]] && a="good" || a="evil"
echo "my name is alexsheen and i am" $a
