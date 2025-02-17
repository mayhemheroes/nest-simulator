# -*- coding: utf-8 -*-
#
# test_connect_fixed_total_number.py
#
# This file is part of NEST.
#
# Copyright (C) 2004 The NEST Initiative
#
# NEST is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# NEST is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with NEST.  If not, see <http://www.gnu.org/licenses/>.

import numpy as np
import unittest
import scipy.stats
import connect_test_base
import nest


HAVE_OPENMP = nest.ll_api.sli_func("is_threaded")


@unittest.skipIf(not HAVE_OPENMP, 'NEST was compiled without multi-threading')
@nest.ll_api.check_stack
class TestFixedTotalNumber(connect_test_base.ConnectTestBase):

    # specify connection pattern and specific params
    rule = 'fixed_total_number'
    conn_dict = {'rule': rule}
    # sizes of source-, target-population and outdegree for connection test
    N1 = 50
    N2 = 70
    Nconn = 100
    conn_dict['N'] = Nconn
    # sizes of source-, target-population and total number of connections for
    # statistical test
    N_s = 20
    N_t = 20
    N = 100
    # Critical values and number of iterations of two level test
    stat_dict = {'alpha2': 0.05, 'n_runs': 200}

    # tested on each mpi process separately
    def testErrorMessages(self):
        got_error = False
        conn_params = self.conn_dict.copy()
        conn_params['allow_autapses'] = True
        conn_params['allow_multapses'] = False
        conn_params['N'] = self.N1 * self.N2 + 1
        try:
            self.setUpNetwork(conn_params)
        except nest.kernel.NESTError:
            got_error = True
        self.assertTrue(got_error)

    def testTotalNumberOfConnections(self):
        conn_params = self.conn_dict.copy()
        self.setUpNetwork(conn_params)
        total_conn = len(nest.GetConnections(self.pop1, self.pop2))
        connect_test_base.mpi_assert(total_conn, self.Nconn, self)
        # make sure no connections were drawn from the target to the source
        # population
        M = connect_test_base.get_connectivity_matrix(self.pop2, self.pop1)
        M_none = np.zeros((len(self.pop1), len(self.pop2)))
        connect_test_base.mpi_assert(M, M_none, self)

    def testStatistics(self):
        conn_params = self.conn_dict.copy()
        conn_params['allow_autapses'] = True
        conn_params['allow_multapses'] = True
        conn_params['N'] = self.N
        for fan in ['in', 'out']:
            expected = connect_test_base.get_expected_degrees_totalNumber(
                self.N, fan, self.N_s, self.N_t)
            pvalues = []
            for i in range(self.stat_dict['n_runs']):
                connect_test_base.reset_seed(i + 1, self.nr_threads)
                self.setUpNetwork(conn_dict=conn_params,
                                  N1=self.N_s, N2=self.N_t)
                degrees = connect_test_base.get_degrees(fan, self.pop1, self.pop2)
                degrees = connect_test_base.gather_data(degrees)
                if degrees is not None:
                    chi, p = connect_test_base.chi_squared_check(degrees, expected)
                    pvalues.append(p)
                connect_test_base.mpi_barrier()
            p = None
            if degrees is not None:
                ks, p = scipy.stats.kstest(pvalues, 'uniform')
            p = connect_test_base.bcast_data(p)
            self.assertGreater(p, self.stat_dict['alpha2'])

    def testAutapsesTrue(self):
        conn_params = self.conn_dict.copy()
        N = 3

        # test that autapses exist
        conn_params['N'] = N * N * N
        conn_params['allow_autapses'] = True
        pop = nest.Create('iaf_psc_alpha', N)
        nest.Connect(pop, pop, conn_params)
        # make sure all connections do exist
        M = connect_test_base.get_connectivity_matrix(pop, pop)
        M = connect_test_base.gather_data(M)
        if M is not None:
            self.assertTrue(np.sum(np.diag(M)) > N)

    def testAutapsesFalse(self):
        conn_params = self.conn_dict.copy()
        N = 3

        # test that autapses were excluded
        conn_params['N'] = N * (N - 1)
        conn_params['allow_autapses'] = False
        pop = nest.Create('iaf_psc_alpha', N)
        nest.Connect(pop, pop, conn_params)
        # make sure all connections do exist
        M = connect_test_base.get_connectivity_matrix(pop, pop)
        connect_test_base.mpi_assert(np.diag(M), np.zeros(N), self)


def suite():
    suite = unittest.TestLoader().loadTestsFromTestCase(TestFixedTotalNumber)
    return suite


def run():
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite())


if __name__ == '__main__':
    run()
