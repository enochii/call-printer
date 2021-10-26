ANALYSIS="build/llvmassignment"
BC_DIR="bc"
GROUND_TRUTH="ground-truth"

# sort_str() {
#     origin_str=$1
#     str=${origin_str//[,]/' '}
#     echo $str
#     return $str
# }

sort_str "s,,s"

file_list=$(ls $BC_DIR)
total=0
correct=0
for bc_file in $file_list; do
    if [[ "${bc_file:6:3}" = ".bc" ]]; then
        total=$(( $total + 1 ))
        actual=$($ANALYSIS "$BC_DIR/$bc_file" 2>&1>/dev/null)
        # echo $actual
        expected=$(cat "$GROUND_TRUTH/${bc_file:0:6}.txt")
        # echo $expected
        actual_no_space=${actual//[[:blank:]]/}
        expected_no_space=${expected//[[:blank:]]/}

        if [[ "$actual_no_space" = "$expected_no_space" ]]; then
            correct=$(( $correct + 1 ))
        else
            echo "$bc_file failed:"
            echo "expected:"
            echo "$expected_no_space"
            echo "given:"
            echo "$actual_no_space"
        fi
    fi
done
echo "$correct/$total"