//===- Hello.cpp - Example code from "Writing an LLVM Pass" ---------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements two versions of the LLVM "Hello World" pass described
// in docs/WritingAnLLVMPass.html
//
//===----------------------------------------------------------------------===//

#include <llvm/Support/CommandLine.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/Support/ToolOutputFile.h>

#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils.h>

#include <llvm/IR/Function.h>
#include <llvm/Pass.h>
#include <llvm/Support/raw_ostream.h>

#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/Bitcode/BitcodeWriter.h>


#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/CallSite.h"

#include <map>
#include <set>
#include <string>
#include <stack>

using namespace std;
using namespace llvm;
static ManagedStatic<LLVMContext> GlobalContext;
static LLVMContext &getGlobalContext() { return *GlobalContext; }
/* In LLVM 5.0, when  -O0 passed to clang , the functions generated with clang will
 * have optnone attribute which would lead to some transform passes disabled, like mem2reg.
 */
struct EnableFunctionOptPass: public FunctionPass {
    static char ID;
    EnableFunctionOptPass():FunctionPass(ID){}
    bool runOnFunction(Function & F) override{
        if(F.hasFnAttribute(Attribute::OptimizeNone))
        {
            F.removeFnAttr(Attribute::OptimizeNone);
        }
        return true;
    }
};

char EnableFunctionOptPass::ID=0;

cl::opt<bool> DumpModuleInfo("dump-module",
                                 cl::desc("Dump Module info into stderr"),
                                 cl::init(false), cl::Hidden);
///!TODO TO BE COMPLETED BY YOU FOR ASSIGNMENT 2
///Updated 11/10/2017 by fargo: make all functions
///processed by mem2reg before this pass.
struct FuncPtrPass : public ModulePass {
  static char ID; // Pass identification, replacement for typeid
  FuncPtrPass() : ModulePass(ID) {}

  
  bool runOnModule(Module &M) override {
    if(DumpModuleInfo) {
      errs() << "Hello: ";
      errs().write_escaped(M.getName()) << '\n';
      M.dump();
      errs()<<"------------------------------\n";
    }
    walkThroughModule(M);
    dumpCallsite();
    return false;
  }

typedef set<const Function*> FuncPtrSet;

private:
  map<const Value *, FuncPtrSet> funcPtrMap;
  map<unsigned, FuncPtrSet> cs2callee; // call site -> callee(function or function pointer)
  stack<Instruction*> callStack;

  void walkThroughModule(const Module & M) {
    const Function *entry = NULL;
    // for(auto const &f : M) {
    //   if(f.isDeclaration() || f.isIntrinsic())
    //     continue;
    //   // llvm::errs() << f.getName();
    //   walkThroughFunc(*entry);
    // }
    for(auto const &f : M) {
      // llvm::errs() << f.getName() << "\n";
      if(f.isDSOLocal())
        entry = &f;
    }
    // TODO: we currently assume the last user-defined function is the "entry"
    assert(entry != NULL && "can not find entry!");
    llvm::errs() << "entry: " << entry->getName() << "\n";
    walkThroughFunc(*entry);
  }

  void walkThroughFunc(const Function& f) {
    for(const_inst_iterator it = inst_begin(f); it != inst_end(f); it++) {
        auto inst = &*it.getInstructionIterator();
        resolvePtrForInstruction(inst);
      }
  }

  void resolvePtrForInstruction(const Instruction *inst) {
    switch (inst->getOpcode())
    {
      case Instruction::Store: {
        
        break;
      }
      case Instruction::Call:
      case Instruction::Invoke: {
        ImmutableCallSite cs(inst);
        assert(cs && "something wrong with call inst?");
        resolvePtrForCall(cs);
        break;
      }
      case Instruction::PHI: {
        const PHINode * phiInst = cast<PHINode>(inst);
        for(unsigned i=0; i<phiInst->getNumIncomingValues(); i++) {
          auto iv = phiInst->getIncomingValue(i);
          // iv->dump();
          if(iv->getType()->isPointerTy()) {
            if(Function *f = dyn_cast<Function>(iv))
              funcPtrMap[phiInst].insert(f);
            else if(funcPtrMap.find(iv) != funcPtrMap.end()) {
              // llvm::errs() << "another pointer in phi node";
              for(auto &f: funcPtrMap[iv]) 
                funcPtrMap[phiInst].insert(f);
            }
          }
        }
        break;
      }
      
      default:
        // inst->dump();
        break;
    }
  }

  void resolvePtrForCall(ImmutableCallSite cs) {
    const Instruction *inst = cs.getInstruction();
    unsigned line = inst->getDebugLoc().getLine();
    if(const Function* f = cs.getCalledFunction()) {
      if(f->isDeclaration() || f->isIntrinsic()) { // external function
        // llvm::outs() << "external fucntion call :";
        // f->dump();
      } else {
        cs2callee[line].insert(f); // TODO: we can do just once!
        doCall(f, cs);
      }
    } else {
      const Value *funcPtr = cs.getCalledValue();
      // funcPtr->dump();
      for(auto &f:funcPtrMap[funcPtr]) {
        cs2callee[line].insert(f);
        doCall(f, cs);
      }
    }
  }

  void doCall(const Function *f, ImmutableCallSite cs) {
    llvm::errs() << "doCall: " << f->getName() << "\n";
    auto argIt = cs.arg_begin();
    auto parIt = f->arg_begin();
    while(argIt != cs.arg_end() && parIt != f->arg_end()) {
      auto parameter = &*parIt;
      const Value* actual = *argIt; // ?
      if(parameter->getType()->isPointerTy() && actual->getType()->isPointerTy())
        funcPtrMap[parameter] = funcPtrMap[actual]; // strong update
      ++argIt; ++parIt;
    }
    walkThroughFunc(*f);
  }

  void dumpCallsite() {
    for(const auto& kv:cs2callee) {
      string res;
      for(auto &f:kv.second) {
        res += f->getName().str() + ", ";
      }
      assert(res.size() > 0 && "no target method!");
      llvm::errs() << kv.first << " : " << res.substr(0, res.size()-2) << "\n";
    }
  }
};


char FuncPtrPass::ID = 0;
static RegisterPass<FuncPtrPass> X("funcptrpass", "Print function call instruction");

static cl::opt<std::string>
InputFilename(cl::Positional,
              cl::desc("<filename>.bc"),
              cl::init(""));


int main(int argc, char **argv) {
   LLVMContext &Context = getGlobalContext();
   SMDiagnostic Err;
   // Parse the command line to read the Inputfilename
   cl::ParseCommandLineOptions(argc, argv,
                              "FuncPtrPass \n My first LLVM too which does not do much.\n");


   // Load the input module
   std::unique_ptr<Module> M = parseIRFile(InputFilename, Err, Context);
   if (!M) {
      Err.print(argv[0], errs());
      return 1;
   }

   llvm::legacy::PassManager Passes;
   	
   ///Remove functions' optnone attribute in LLVM5.0
   Passes.add(new EnableFunctionOptPass());
   ///Transform it to SSA
   Passes.add(llvm::createPromoteMemoryToRegisterPass());

   /// Your pass to print Function and Call Instructions
   Passes.add(new FuncPtrPass());
   Passes.run(*M.get());
}

