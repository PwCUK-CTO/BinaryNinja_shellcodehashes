####### NOTICE #######

# This plugin is an adaptation from the original mandiant ShellcodeHashes plugin for IDA found at:
# https://github.com/mandiant/flare-ida/blob/master/python/flare/shellcode_hash_search.py
# This adaptation converts the IDA plugin to a Binary Ninja plugin
# Python comments have been added to bound the modified sections of code and highlight any changes.
# These comments begin with the following string: "# CHANGE: "

####### END NOTICE #######

# CHANGE: Original Mandiant code from here

########################################################################
# Copyright 2012 Mandiant
# Copyright 2014,2018 FireEye
#
# Mandiant licenses this file to you under the Apache License, Version
# 2.0 (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at:
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.
########################################################################

import sys
import ctypes
import logging
import os.path
import sqlite3

# CHANGE: Omitted unnecessary import statements and python code from original script here

############################################################
# SQL queries
############################################################

sql_lookup_hash_value='''
select
    h.hash_val, 
    h.symbol_name, 
    l.lib_name, 
    t.hash_name, 
    t.hash_size
from 
    symbol_hashes h, 
    source_libs l, 
    hash_types t 
where 
    h.hash_val=? and 
    h.lib_key=l.lib_key and 
    h.hash_type=t.hash_type;
'''

sql_lookup_hash_type_value='''
select
    h.hash_val, 
    h.symbol_name, 
    l.lib_name, 
    t.hash_name, 
    t.hash_size
from 
    symbol_hashes h, 
    source_libs l, 
    hash_types t 
where 
    h.hash_val=? and 
    h.lib_key=l.lib_key and 
    h.hash_type=t.hash_type and
    h.hash_type=?;
'''

sql_get_all_hash_types='''
select 
    hash_type,
    hash_size,
    hash_name,
    hash_code
from hash_types;
'''

sql_find_source_lib_by_name='''
select
    lib_key
from 
    source_libs
where 
    lib_name=?;
'''

sql_adjust_cache_size='''
PRAGMA cache_size=200000;
'''

############################################################
# Row wrappers
############################################################

class SymbolHash(object):
    def __init__(self, hashVal, symbolName, libName, hashName, hashSize):
        self.hashVal = hashVal
        self.symbolName = symbolName
        self.libName = libName
        self.hashName = hashName
        self.hashSize = hashSize

    def __str__(self):
        return '%s:0x%08x %s!%s' % (self.hashName, self.hashVal, self.libName, self.symbolName )


class HashType(object):
    def __init__(self, hashType, hashSize, hashName, hashCode):
        self.hashType = hashType
        self.hashSize = hashSize
        self.hashName = hashName
        self.hashCode = hashCode

class HashHit(object):
    def __init__(self, ea, symHash):
        self.ea = ea
        self.symHash = symHash

############################################################
# 
############################################################

class DbStore(object):
    '''
    Used to access the hash db.
    '''
    def __init__(self, dbPath):
        self.dbPath = dbPath
        self.conn = sqlite3.connect(dbPath)
        self.conn.execute(sql_adjust_cache_size)

    def close(self):
        self.conn.close()
        self.conn = None

    def getSymbolByHash(self, hashVal):
        '''
        Returns list of SymbolHash objects for requested hashvalue.
        List is empty for no hits
        '''
        retList = []
        cur = self.conn.execute(sql_lookup_hash_value, (ctypes.c_int64(hashVal).value,))
        for row in cur:
            #logger.debug("Found hits for value: %08x", hashVal)
            sym = SymbolHash(*row)
            retList.append(sym)
        return retList

    def getAllHashTypes(self):
        '''
        Returns a list of HashType objects stored in the DB.
        '''
        retArr = []
        cur = self.conn.execute(sql_get_all_hash_types)
        for row in cur:
            retArr.append(HashType(*row))
        return retArr

    def getSymbolByTypeHash(self, hashType, hashVal):
        '''
        Returns list of SymbolHash objects for requested hashvalue.
        List is empty for no hits
        '''
        retList = []
        cur = self.conn.execute(sql_lookup_hash_type_value, (ctypes.c_int64(hashVal).value, hashType))

        for row in cur:
            #logger.debug("Found hits for value: %08x", hashVal)
            sym = SymbolHash(*row)
            retList.append(sym)
        return retList

############################################################
# 
############################################################

# CHANGE: End original Mandiant code here.
# CHANGE: The following code is based on, but modified from, the original Mandiant shellcodehashes plugin
# CHANGE: The core of the changes are to convert the code from the IDA API to the Binary Ninja API
# CHANGE: Known limitations:
# CHANGE:   Ability to choose options in a GUI has not been implemented
# CHANGE:   Ability to search through non-code data has not been implemented

from binaryninja import *

class SearchParams(object):
    '''
    Just used to track the user provided search parameters.
    '''
    def __init__(self):
        self.useXORSeed = False
        self.XORSeed = 0

        #hashTypes: list of HashTypes user confirmed to process
        self.hashTypes = []

############################################################
# SearchParams
############################################################

def find_constants(instr):
    if isinstance(instr, Constant):
        return [instr.constant, instr.address]

class ShellcodeHashSearcher(object):
    def __init__(self, dbstore, params, bv):
        self.dbstore = dbstore
        self.params = params
        self.bv = bv

    def processCode(self):
        # TODO - add in option to use current selection
        # TODO - add in option to search for .data/.rdata constants rather than just instruction args
        self.lookForOpArgs()

    def run(self):
        log.log_info('Starting up')
        self.processCode()
        self.dbstore.close()
        log.log_info('Done')

    def lookForOpArgs(self):
        for func in self.bv.functions:
            try:
                for opval, addr in func.mlil.traverse(find_constants):
                    if self.params.useXORSeed:
                        opval = opval ^ self.params.XORSeed
                    for h in self.params.hashTypes:
                        hits = self.dbstore.getSymbolByTypeHash(h.hashType, opval)
                        for sym in hits:
                            log.log_info("0x%08x: %s" % (addr, str(sym)))
                            self.markupLine(addr, sym)
            except Exception as err:
               log.warn("Exception: %s", str(err))

    def markupLine(self, loc, sym):
        comm = '%s!%s' % (sym.libName, sym.symbolName)
        log.log_info("Making comment @ 0x%08x: %s" % (loc, comm))
        self.bv.set_comment_at(loc, str(comm))

###################################################################
#
###################################################################

class SearchLauncher(object):
    def __init__(self, bv):
        self.params = SearchParams()
        self.bv = bv

    def run(self):
        try:
            log.log_info("Starting up")
            dbFile = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'shellcode_hashes', 'sc_hashes.db'))
            log.log_info('Trying default db path: %s' % dbFile)
            if not os.path.exists(dbFile):
                dbFile = get_open_filename_input("Select shellcode hash database", "*.db")
                if (dbFile is None) or (not os.path.isfile(dbFile)):
                    log.log_info("No file select. Stopping now")
                    return
            self.dbstore = DbStore(dbFile)
            log.log_info("Loaded db file: %s" % dbFile)
            self.getParams()
            searcher = ShellcodeHashSearcher(self.dbstore, self.params, self.bv)
            log.log_info('Starting to run the searcher now')
            searcher.run()
            log.log_info("Done")
        except RejectionException:
            log.log_info('User canceled action')
        except Exception as err:
            log.log_info("Exception caught: %s" % str(err))

    def getParams(self):
        log.log_info('Getting options')
        self.promptForHashTypes()
        self.params.useXORSeed = get_choice_input("Use XORSeed?", "", ["No", "Yes"])
        if self.params.useXORSeed:
            self.params.XORSeed = get_int_input("Enter hex XORSeed (either hex or decimal format)", "")

    def promptForHashTypes(self):
        '''
        Currently defaults to searching all algorithms in the database.
        TODO - display a chooser to allow users to limit the selection to particular algorithms
        '''
        # grab all by default
        hashTypes = self.dbstore.getAllHashTypes()
        
        # we used to prompt y/n for each one. too obnoxious, just force all hashes
        self.params.hashTypes = hashTypes

###################################################################
#
###################################################################

def shellcode_hash_search(bv):

    launcher = SearchLauncher(bv)
    launcher.run()

PluginCommand.register("ShellcodeHashes", "Find and annotate shellcode hash values", shellcode_hash_search)