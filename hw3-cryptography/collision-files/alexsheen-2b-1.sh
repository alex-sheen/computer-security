cat << 'EOF' > outfile
                                         �ޖr�<���X���ю��YN�(�cz�J��+���N�+��g݂���@���7ǎ�������tX����۾7�%�[�@�\�*&&��9�G�eV�>��xkl7���fR����U�3c�x
EOF
isInFile=$(cat outfile | grep -c "YN")
[[ $isInFile = 1 ]] && a="good" || a="evil"
echo "my name is alexsheen and i am" $a
