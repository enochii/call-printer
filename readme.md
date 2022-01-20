## Call Printer

Assignment 2 of UCAS compiler homework, for more information you can refer to [this blog](https://enochii.github.io/posts/2021/11/08/Implement-a-call-printer.html).

### Requirement

Print all possible target methods in a call statement, a call may be invoked directly or indirectly(by a function pointer).

This implementation DO NOT handle loop(for/while). Check `assign2-test` folder for more details. The expected answers are in `ground-truth`.

### Structure

```shell
.
├── assign2-tests # test cases
├── CMakeLists.txt 
├── grade.sh # grading script
├── ground-truth # ground truth
├── LLVMAssignment.cpp # implementation
├── note.md # `simple notes`
├── readme.md 
└── sh # some util scripts need by `grade.sh`
```
