from __future__ import division
import os
import sys
import site
import shutil
import logging

from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.block import CodeBlockIterator
from ghidra.program.model.block import CodeBlockReference 
from ghidra.program.model.block import CodeBlockReferenceIterator 
from ghidra.program.model.listing import CodeUnitIterator;
from ghidra.program.model.listing import Function;
from ghidra.program.model.listing import FunctionManager;
from ghidra.program.model.listing import Listing;
from ghidra.program.database.code import InstructionDB
from ghidra.program.model.symbol import SourceType

SAVE_DIR = "./cfg/"

def addBB(bb, G, bb_func_map):
    listing = currentProgram.getListing();
    # iter over the instructions
    codeUnits = listing.getCodeUnits(bb, True)
    lastInstStart = 0x0
    lastInstEnd = 0x0

    bb_tbl_rows = ''
    i = 0
    while codeUnits.hasNext():
        codeUnit = codeUnits.next()
        # check if the code unit is the instruction
        if not isinstance(codeUnit, InstructionDB):
            continue
        # Record address of first instruction
        if i == 0:
            firstInstStart = codeUnit.getAddress().getOffset()

        lastInstStart = codeUnit.getAddress().getOffset()
        lastInstEnd = lastInstStart + codeUnit.getLength()

        bb_tbl_rows += ('''
      <TR>
        <TD PORT="insn_%x" ALIGN="RIGHT"><FONT FACE="monospace">%x: </FONT></TD>
        <TD ALIGN="LEFT"><FONT FACE="monospace">%s</FONT></TD>
        <TD>&nbsp;&nbsp;&nbsp;</TD> // for spacing
      </TR>''' % (lastInstStart, lastInstStart, str(codeUnit)))
        i += 1 # Bump Counter

    bb_tbl_node = ('''  bb_%x [shape=plaintext label=<
    <TABLE BORDER="1" CELLBORDER="0" CELLSPACING="0">%s
    </TABLE>>];\n''' % (bb.getMinAddress().getOffset(), bb_tbl_rows))

    bb_func_map[bb.getMinAddress().getOffset()] = \
        'bb_%x:insn_%x' % (bb.getMinAddress().getOffset(), firstInstStart)

    # add node
    G += bb_tbl_node

    return G

def addSuccessors(bb_func_set, bb_func_map, G):
    listing = currentProgram.getListing();

    for bb in bb_func_set:
        codeUnits = listing.getCodeUnits(bb, True)
        lastInstStart = 0x0
        lastInstEnd = 0x0
        cur_bb_str = bb_func_map[bb.getMinAddress().getOffset()]
        sucSet = set()

        while codeUnits.hasNext():
            codeUnit = codeUnits.next()

            if not isinstance(codeUnit, InstructionDB):
                continue

            lastInstStart = codeUnit.getAddress().getOffset()
            lastInstEnd = lastInstStart + codeUnit.getLength()
            successors = bb.getDestinations(monitor)

        while successors.hasNext():
            sucBBRef = successors.next()
            sucBBRefAddr = sucBBRef.getReferent().getOffset()
            sucBB = sucBBRef.getDestinationBlock()
            sucOffset = sucBB.getFirstStartAddress().getOffset()

            if sucOffset in sucSet:
                continue

            if sucOffset not in bb_func_map:
                continue

            currInsnAddr = sucBBRef.getReferent().getOffset()
            currBBAddr = bb.getMinAddress().getOffset()
            flowType = sucBBRef.getFlowType()

            if (flowType.isJump() and flowType.isUnConditional()) or flowType.isFallthrough():
                edgeAttrs = 'color=gray style=dashed'
            elif flowType.isCall() and flowType.isUnConditional():
                edgeAttrs = 'color=cyan4 style=dashed'
            elif flowType.isJump() and flowType.isConditional():
                edgeAttrs = 'color=gray style=solid'
            elif flowType.isCall() and flowType.isConditional():
                edgeAttrs = 'color=cyan4 style=solid'
            else:
                edgeAttrs = 'color=gray style=dotted'

            edgeAttrs += ' tooltip="%s"' % str(flowType)
            G += (('  bb_%x:insn_%x -> %s [%s];\n') \
                    % (currBBAddr, currInsnAddr, bb_func_map[sucOffset], 
                       edgeAttrs))

            sucSet.add(sucOffset)

    return G


def dumpBlocks():
    bbModel = BasicBlockModel(currentProgram)
    functionManager = currentProgram.getFunctionManager()

    G = ('''digraph {
  newrank=true;
  // Flow Type Legend
  subgraph cluster_01 { 
    rank=same;
    node [shape=plaintext]
    label = "Legend";
    key [label=<<table border="0" cellpadding="2" cellspacing="0" cellborder="0">
                  <tr><td align="right" port="i1">Jump/Fallthrough</td></tr>
                  <tr><td align="right" port="i2">Call</td></tr>
                  <tr><td align="right" port="i3">Conditional Jump</td></tr>
                  <tr><td align="right" port="i4">Conditional Call</td></tr>
                  <tr><td align="right" port="i5">Other</td></tr>
               </table>>];
    key2 [label=<<table border="0" cellpadding="2" cellspacing="0" cellborder="0">
                   <tr><td port="i1">&nbsp;</td></tr>
                   <tr><td port="i2">&nbsp;</td></tr>
                   <tr><td port="i3">&nbsp;</td></tr>
                   <tr><td port="i4">&nbsp;</td></tr>
                   <tr><td port="i5">&nbsp;</td></tr>
                </table>>];
    key:i1:e -> key2:i1:w [color=gray style=dashed];
    key:i2:e -> key2:i2:w [color=cyan4 style=dashed];
    key:i3:e -> key2:i3:w [color=gray];
    key:i4:e -> key2:i4:w [color=cyan4];
    key:i5:e -> key2:i5:w [color=gray style=dotted];
  }
''')

    # record the basic block that has been added by functions and get all functions
    bb_set = set()
    funcs_set = set()
    bb_func_map = dict()    

    name = "main"
    funcs = getGlobalFunctions(name)
    addr = None
    for func in funcs:
        addr = func.getEntryPoint()
	
    funct = functionManager.getFunctionContaining(addr)

    codeBlockIterator = bbModel.getCodeBlocksContaining(funct.getBody(), monitor)
    bb_func_set = set()
    
    while codeBlockIterator.hasNext(): 
        bb = codeBlockIterator.next() 
        bb_set.add(bb.getMinAddress().getOffset())
        bb_func_set.add(bb)
        G = addBB(bb, G, bb_func_map)
    G = addSuccessors(bb_func_set, bb_func_map, G)
    G += '}'
    with open(SAVE_DIR + 'result.dot', 'w') as dot_output:
        dot_output.write(G)

    """
    for func in functionManager.getFunctions(True):
        func_va = func.getEntryPoint().getOffset()
        if func_va in funcs_set:
            continue

        funcs_set.add(func_va)
        codeBlockIterator = bbModel.getCodeBlocksContaining(func.getBody(), monitor)
        bb_func_set = set()

        # iter over the basic blocks
        while codeBlockIterator.hasNext(): 
            bb = codeBlockIterator.next() 
            bb_set.add(bb.getMinAddress().getOffset())
            bb_func_set.add(bb)
            G = addBB(bb, G, bb_func_map)

        G = addSuccessors(bb_func_set, bb_func_map, G)
    G += '}'

    with open(SAVE_DIR + 'result.dot', 'w') as dot_output:
        dot_output.write(G)
    """

if __name__ == "__main__":	
	# Remove the existing path and Save CFG
    if os.path.exists(SAVE_DIR):
	    shutil.rmtree(SAVE_DIR)
		
    os.mkdir(SAVE_DIR)

    dumpBlocks()

