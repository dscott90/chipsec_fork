# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2024, Intel Corporation
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# Contact information:
# chipsec@intel.com
#

""""
To execute: python[3] -m unittest tests.utilcmd.mem_cmd.test_mem_cmd
"""

import unittest
import os

from chipsec.library.file import get_main_dir
from unittest.mock import patch
from tests.utilcmd.run_chipsec_util import setup_run_destroy_util
from chipsec.testcase import ExitCode

class TestMemUtilCmd(unittest.TestCase):
    def test_readval(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        iommu_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "mem_cmd", "mem_cmd_readval_1.json")
        retval = setup_run_destroy_util(init_replay_file, "mem", "readval 0xFED40000 dword", util_replay_file=iommu_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    @patch('chipsec.utilcmd.mem_cmd.write_file')
    def test_read(self, mock_write_file) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        iommu_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "mem_cmd", "mem_cmd_read_1.json")
        retval = setup_run_destroy_util(init_replay_file, "mem", "read 0x41E 0x10 mock_buffer.bin", util_replay_file=iommu_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)