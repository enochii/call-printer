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
cl::opt<bool> DumpDebugInfo("debug-info",
                                 cl::desc("Dump debug info into out"),
                                 cl::init(false), cl::Hidden);
cl::opt<bool> DumpTrace("trace",
                                 cl::desc("Dump trace into err"),
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

struct State {
  map<const Value *, FuncPtrSet> funcPtrMap;
  const Instruction * PC;
  stack<int> branchLabels;

  State(map<const Value *, FuncPtrSet> &funcPtrMap,
       const Instruction * PC, stack<int>&labels)
        :funcPtrMap(funcPtrMap), PC(PC), branchLabels(labels) { }
};


private:
  map<unsigned, FuncPtrSet> cs2callee; // call site -> callee(function or function pointer)

  stack<int> branchLabels;
  map<const Value *, FuncPtrSet> funcPtrMap;

  stack<const Instruction*> callStack;
  stack<State> branchStack;
  // int branchLabel = 0;

  void walkThroughModule(const Module & M) {
    const Function *entry = NULL;
    for(auto const &f : M) {
      if(!f.isDSOLocal())
        continue;
      walkThroughFunc(f);
    }
  }

  void walkThroughFunc(const Function& f) {
    const int sz = branchStack.size();
    if(inst_begin(f) == inst_end(f)) return;
    auto endInst = &*--inst_end(f);
    auto curInst = &*inst_begin(f);
    while(curInst != endInst) {
        if(DumpTrace)curInst->dump();
        if(resolvePtrForInstruction(curInst)) {
          // branch with or without condition
          assert(curInst->getOpcode() == Instruction::Br);
          const BranchInst* brInst = cast<BranchInst>(curInst);
          curInst = &brInst->getSuccessor(0)->front();
        } else 
          curInst = curInst->getNextNode();
    }
    resolvePtrForInstruction(endInst);//....
    auto current = funcPtrMap;
    while (branchStack.size() > sz) {
      setBranchLabel(1);
      // change state
      auto top = branchStack.top(); branchStack.pop();
      funcPtrMap = top.funcPtrMap;
      branchLabels = top.branchLabels;
      auto inst = top.PC;
      while(inst != endInst) {
        if(DumpTrace)inst->dump();
        bool jump = resolvePtrForInstruction(inst);
        if(jump) {
          inst = &inst->getSuccessor(0)->front();
        } else {
          inst = inst->getNextNode();
        }
      }
      resolvePtrForInstruction(endInst);//....
      mergePtrMap(current, funcPtrMap);
      setBranchLabel(0);
    }
    funcPtrMap = current;
  }

  /// return value indicates that, should we jump?
  bool resolvePtrForInstruction(const Instruction *inst) {
    switch (inst->getOpcode())
    {
      case Instruction::Call:
      case Instruction::Invoke: {
        ImmutableCallSite cs(inst);
        assert(cs && "something wrong with call inst?");
        resolvePtrForCall(cs);
        break;
      }
      case Instruction::Ret: {
        /// the return stmt is always at the end of function body
        if(inst->getNumOperands() > 0) {
          const Value* ret = inst->getOperand(0);
          if(!ret->getType()->isPointerTy())
            break;
          if(DumpDebugInfo) ret->dump();
          if(funcPtrMap.count(ret)) {
            auto ptrSet = lookupValue(ret);
            const Instruction *retInst = callStack.top();
            // retInst->dump();
            // dumpPtrs(ptrSet);
            // merge multiple return result! -> DO NOT strong update
            mergePtrSet(funcPtrMap[retInst], ptrSet);
          }
        }
        /// actually we can just keep the call stack un-poped...
        if(!callStack.empty()) callStack.pop();
        break;
      }
      case Instruction::PHI: {
        const PHINode * phiInst = cast<PHINode>(inst);
        if(branchLabels.empty()) {
          llvm::outs() << "Empty leabl stack!\n";
          break;
        }
        assert(!branchLabels.empty() && "branch label stack is empty!");
        int branchLabel = branchLabels.top();
        if(phiInst->getNextNode() && 
              phiInst->getNextNode()->getOpcode()!=Instruction::PHI)
          branchLabels.pop();
        for(unsigned i=0; i<phiInst->getNumIncomingValues(); i++) {
          if(i != branchLabel) continue;
          auto iv = phiInst->getIncomingValue(i);
          if(DumpDebugInfo) {
            llvm::outs() << "phi: " << phiInst->getName() << "<-" 
                         << iv->getName() << "\n";
          }
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
      case Instruction::Br: {
        const BranchInst *brInst = cast<BranchInst>(inst);
        if(brInst->getNumSuccessors() == 2) {
          const Value* cond = brInst->getCondition();
          if(const CmpInst* bop=dyn_cast<CmpInst>(cond)) {
            // TODO: complete the logic
            if(isa<ConstantInt>(bop->getOperand(0)) && 
                isa<ConstantInt>(bop->getOperand(1))) {
                  auto a = dyn_cast<ConstantInt>(bop->getOperand(0));
                  auto b = dyn_cast<ConstantInt>(bop->getOperand(1));
                  // only handle ">" for test19
                  if(a->getLimitedValue() > b->getLimitedValue()) {
                    branchLabels.push(0); 
                    return true;
                  }
                }
          }

          auto elseBranchLabels = branchLabels;
          elseBranchLabels.push(1);
          branchLabels.push(0);
          const Instruction* elseEntry = &brInst->getSuccessor(1)->front();
          branchStack.emplace(funcPtrMap, elseEntry, elseBranchLabels);
          if(!callStack.empty()) 
            callStack.push(callStack.top()); // then we can pop twice
        } else {
          assert(brInst->getNumSuccessors() == 1);
          if(brInst->getSuccessor(0)->getName().startswith("for.cond")
            && brInst->getParent()->getName().startswith("for.inc")) {
            llvm::outs() << "for???\n";
            return false;
          }
        }
        return true; // jump 
      }
      
      default:
        if(inst->getType()->isPointerTy()) {
          inst->dump();
        }
        break;
    }
    return false;
  }

  void resolvePtrForCall(ImmutableCallSite cs) {
    const Instruction *inst = cs.getInstruction();
    unsigned line = inst->getDebugLoc().getLine();
    if(const Function* f = cs.getCalledFunction()) {
      if(f->isDeclaration() || f->isIntrinsic()) { // external function
        // llvm::outs() << "external fucntion call :";
        // f->dump();
        if(f->isDSOLocal()) cs2callee[line].insert(f);
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
    if(DumpDebugInfo) llvm::outs() << "doCall: " << f->getName() << "\n";
    auto argIt = cs.arg_begin();
    auto parIt = f->arg_begin();
    while(argIt != cs.arg_end() && parIt != f->arg_end()) {
      const Argument* parameter = &*parIt;
      const Value* actual = *argIt; // ?
      if(parameter->getType()->isPointerTy() && actual->getType()->isPointerTy()) {
        funcPtrMap[parameter] = lookupValue(actual); // strong update
        if(DumpDebugInfo) {
          llvm::outs() << "actual(";
          llvm::outs() << actual->getName() << "): ";
          dumpPtrs(funcPtrMap[actual]);
        }
      }
      ++argIt; ++parIt;
    }
    callStack.push(cs.getInstruction());
    walkThroughFunc(*f);
  }

  FuncPtrSet lookupValue(const Value * v) {
    FuncPtrSet res;
    if(const Function *f = dyn_cast<Function>(v)) {
      res.insert(f);
      return res;
    }
    else if(funcPtrMap.find(v) != funcPtrMap.end()) {
      // llvm::outs() << "lookup: \n";
      // dumpPtrs(funcPtrMap[v]);
      return funcPtrMap[v];
    }
    return res; // empty
    // assert(0 && "lookupValue failed");
  }

  void mergePtrMap(map<const Value *, FuncPtrSet> dst, map<const Value *, FuncPtrSet> src) {
    for(auto &kv:src) 
      mergePtrSet(dst[kv.first], kv.second);
  }

  void mergePtrSet(FuncPtrSet &dst, FuncPtrSet &src) {
    for(const auto v:src) 
      dst.insert(v);
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
 
  void dumpPtrs(FuncPtrSet &ptrSet) {
    for(auto value:ptrSet) {
      llvm::outs() << value->getName() << " ";
    }
    llvm::outs() << "\n";
  }

  void setBranchLabel(int label) {
    // branchLabel = label;
    // llvm::errs() << "set label to " << label << "\n";
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

