# build
mkdir build
cd build
cmake –DLLVM_DIR=/usr/local/llvm10d -DCMAKE_BUILD_TYPE=Debug ../.
make
cd ..

source compile.sh # generate .bc

# grading
ANALYSIS="build/llvmassignment"
BC_DIR="bc"
GROUND_TRUTH="ground-truth"

file_list=$(ls $BC_DIR)
total=0
correct=0
for bc_file in $file_list; do
    if [[ "${bc_file:6:3}" = ".bc" ]]; then
        total=$(( $total + 1 ))
        actual=$($ANALYSIS "$BC_DIR/$bc_file" 2>&1>/dev/null)
        expected=$(cat "$GROUND_TRUTH/${bc_file:0:6}.txt")
        # format 
        actual=$(python format_helper.py "$actual")
        expected=$(python format_helper.py "$expected")

        if [[ "$actual" = "$expected" ]]; then
            echo "$bc_file passed"
            correct=$(( $correct + 1 ))
        else
            echo "$bc_file failed:"
            echo "expected:"
            echo "$expected"
            echo "given:"
            echo "$actual"
        fi
    fi
done
echo "$correct/$total"