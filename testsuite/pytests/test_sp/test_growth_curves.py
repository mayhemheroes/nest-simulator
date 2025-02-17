# -*- coding: utf-8 -*-
#
# test_growth_curves.py
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

from scipy.integrate import quad
import math
import numpy
from numpy import testing
import unittest
import nest

HAVE_OPENMP = nest.ll_api.sli_func("is_threaded")


class SynapticElementIntegrator:
    """
    Generic class which describes how to compute the number of
    Synaptic Element based on Ca value
    Each derived class should overwrite the get_se(self, t) method
    """

    def __init__(self, tau_ca=10000.0, beta_ca=0.001):
        """
        Constructor

        :param tau_ca (float): time constant of Ca decay
        :param beta_ca (float): each spike increase Ca value by this value
        """
        self.tau_ca = tau_ca
        self.beta_ca = beta_ca

        self.t_minus = 0
        self.ca_minus = 0
        self.se_minus = 0

    def reset(self):
        self.t_minus = 0
        self.ca_minus = 0
        self.se_minus = 0

    def handle_spike(self, t):
        """
        Add beta_ca to the value of Ca at t = spike time
        Also update the number of synaptic element

        :param t (float): spike time
        """
        assert t >= self.t_minus
        # Update the number of synaptic element
        self.se_minus = self.get_se(t)
        # update Ca value
        self.ca_minus = self.get_ca(t) + self.beta_ca
        self.t_minus = t

    def get_ca(self, t):
        """
        :param t (float): current time

        :return: Ca value
        """
        assert t >= self.t_minus
        ca = self.ca_minus * math.exp((self.t_minus - t) / self.tau_ca)
        if ca > 0:
            return ca
        else:
            return 0

    def get_se(self, t):
        """
        :param t (float): current time

        :return: Number of synaptic element

        Should be overwritten
        """
        return 0.0


class LinearExactSEI(SynapticElementIntegrator):
    """
    Compute the number of synaptic element corresponding to a
    linear growth curve
    dse/dCa = nu * (1 - Ca/eps)
    Use the exact solution
    """

    def __init__(self, eps=0.7, growth_rate=1.0, *args, **kwargs):
        """
        Constructor

        :param eps: fix point
        :param growth_rate: scaling of the growth curve

        .. seealso:: SynapticElementIntegrator()
        """
        super(LinearExactSEI, self).__init__(*args, **kwargs)
        self.eps = eps
        self.growth_rate = growth_rate

    def get_se(self, t):
        """
        :param t (float): current time
        :return: Number of synaptic element
        """
        assert t >= self.t_minus
        se = 1 / self.eps * (
            self.growth_rate * self.tau_ca * (
                self.get_ca(t) - self.ca_minus
            ) + self.growth_rate * self.eps * (t - self.t_minus)
        ) + self.se_minus
        if se > 0:
            return se
        else:
            return 0


class LinearNumericSEI(SynapticElementIntegrator):
    """
    Compute the number of synaptic element corresponding to a
    linear growth curve
    dse/dCa = nu * (1 - Ca/eps)
    Use numerical integration (see scipy.integrate.quad)
    """

    def __init__(self, eps=0.7, growth_rate=1.0, *args, **kwargs):
        """
        Constructor

        :param eps: fix point
        :param growth_rate: scaling of the growth curve

        .. seealso:: SynapticElementIntegrator()
        """
        super(LinearNumericSEI, self).__init__(*args, **kwargs)
        self.eps = eps
        self.growth_rate = growth_rate

    def get_se(self, t):
        """
        :param t (float): current time
        :return: Number of synaptic element
        """
        assert t >= self.t_minus
        se = self.se_minus + quad(self.growth_curve, self.t_minus, t)[0]
        if se > 0:
            return se
        else:
            return 0

    def growth_curve(self, t):
        return self.growth_rate * (1.0 - (self.get_ca(t) / self.eps))


class GaussianNumericSEI(SynapticElementIntegrator):
    """
    Compute the number of synaptic element corresponding to a
    linear growth curve
    dse/dCa = nu * (2 * exp( ((Ca - xi)/zeta)^2 ) - 1)
    with:
        xi = (eta + eps) / 2.0
        zeta = (eta - eps) / (2.0 * sqrt(ln(2.0)))

    Use numerical integration (see scipy.integrate.quad)
    """

    def __init__(self, eta=0.1, eps=0.7, growth_rate=1.0, *args, **kwargs):
        """
        Constructor

        :param eps: low fix point
        :param eta: high fix point
        :param growth_rate: scaling of the growth curve

        .. seealso:: SynapticElementIntegrator()
        """
        super(GaussianNumericSEI, self).__init__(*args, **kwargs)
        self.zeta = (eta - eps) / (2.0 * math.sqrt(math.log(2.0)))
        self.xi = (eta + eps) / 2.0
        self.growth_rate = growth_rate

    def get_se(self, t):
        """
        :param t (float): current time
        :return: Number of synaptic element
        """
        assert t >= self.t_minus
        se = self.se_minus + quad(self.growth_curve, self.t_minus, t)[0]
        if se > 0:
            return se
        else:
            return 0

    def growth_curve(self, t):
        return self.growth_rate * (
            2 * math.exp(
                - math.pow((self.get_ca(t) - self.xi) / self.zeta, 2)
            ) - 1
        )


class SigmoidNumericSEI(SynapticElementIntegrator):

    """
    Compute the number of synaptic element corresponding to a
    sigmoid growth curve
    dse/dCa = nu * ((2.0 / exp( (Ca - eps)/psi)) - 1.0)

    Use numerical integration (see scipy.integrate.quad)
    """

    def __init__(self, eps=0.7, growth_rate=1.0, psi=0.1, *args, **kwargs):
        """
        Constructor

        :param eps: set point
        :param psi: controls width of growth curve
        :param growth_rate: scaling of the growth curve

        .. seealso:: SynapticElementIntegrator()
        """
        super(SigmoidNumericSEI, self).__init__(*args, **kwargs)
        self.eps = eps
        self.psi = psi
        self.growth_rate = growth_rate

    def get_se(self, t):
        """
        :param t (float): current time
        :return: Number of synaptic element
        """
        assert t >= self.t_minus
        se = self.se_minus + quad(self.growth_curve, self.t_minus, t)[0]
        if se > 0:
            return se
        else:
            return 0

    def growth_curve(self, t):
        return self.growth_rate * (
            (2.0 / (1.0 + math.exp(
                (self.get_ca(t) - self.eps) / self.psi
            ))) - 1.0
        )


@unittest.skipIf(not HAVE_OPENMP, 'NEST was compiled without multi-threading')
class TestGrowthCurve(unittest.TestCase):
    """
    Unittest class to test the GrowthCurve used with nest
    """

    rtol = 5e-1

    def setUp(self):
        nest.ResetKernel()
        nest.set_verbosity('M_ERROR')
        nest.total_num_virtual_procs = 4
        nest.rng_seed = 1

        self.sim_time = 10000.0
        self.sim_step = 100

        nest.structural_plasticity_update_interval = self.sim_time + 1

        self.se_integrator = []
        self.sim_steps = None
        self.ca_nest = None
        self.ca_python = None
        self.se_nest = None
        self.se_python = None

        # build
        self.pop = nest.Create('iaf_psc_alpha', 10)
        self.spike_recorder = nest.Create('spike_recorder')
        nest.Connect(self.pop, self.spike_recorder, 'all_to_all')
        noise = nest.Create('poisson_generator')
        nest.SetStatus(noise, {"rate": 800000.0})
        nest.Connect(noise, self.pop, 'all_to_all')

    def simulate(self):
        self.sim_steps = numpy.arange(0, self.sim_time, self.sim_step)
        self.ca_nest = numpy.zeros(
            (len(self.pop), len(self.sim_steps)))
        self.ca_python = numpy.zeros(
            (len(self.se_integrator), len(self.sim_steps)))
        self.se_nest = numpy.zeros(
            (len(self.pop), len(self.sim_steps)))
        self.se_python = numpy.zeros(
            (len(self.se_integrator), len(self.sim_steps)))

        for t_i, t in enumerate(self.sim_steps):
            for n_i in range(len(self.pop)):
                self.ca_nest[n_i][t_i], synaptic_elements = nest.GetStatus(
                    self.pop[n_i], ('Ca', 'synaptic_elements'))[0]
                self.se_nest[n_i][t_i] = synaptic_elements['se']['z']
            nest.Simulate(self.sim_step)

        tmp = nest.GetStatus(self.spike_recorder, 'events')[0]
        spikes_all = tmp['times']
        senders_all = tmp['senders']
        for n_i, n in enumerate(self.pop):
            spikes = spikes_all[senders_all == n.get('global_id')]
            [sei.reset() for sei in self.se_integrator]
            spike_i = 0
            for t_i, t in enumerate(self.sim_steps):
                while spike_i < len(spikes) and spikes[spike_i] <= t:
                    [sei.handle_spike(spikes[spike_i])
                     for sei in self.se_integrator]
                    spike_i += 1
                for sei_i, sei in enumerate(self.se_integrator):
                    self.ca_python[sei_i, t_i] = sei.get_ca(t)
                    self.se_python[sei_i, t_i] = sei.get_se(t)

            for sei_i, sei in enumerate(self.se_integrator):
                testing.assert_allclose(self.ca_nest[n_i], self.ca_python[sei_i], rtol=self.rtol)
                testing.assert_allclose(self.se_nest[n_i], self.se_python[sei_i], rtol=self.rtol)

    def test_linear_growth_curve(self):
        beta_ca = 0.0001
        tau_ca = 10000.0
        growth_rate = 0.0001
        eps = 0.10
        nest.SetStatus(
            self.pop,
            {
                'beta_Ca': beta_ca,
                'tau_Ca': tau_ca,
                'synaptic_elements': {
                    'se': {
                        'growth_curve': 'linear',
                        'growth_rate': growth_rate,
                        'eps': eps,
                        'z': 0.0
                    }
                }
            }
        )
        self.se_integrator.append(LinearExactSEI(
            tau_ca=tau_ca, beta_ca=beta_ca, eps=eps, growth_rate=growth_rate))
        self.se_integrator.append(LinearNumericSEI(
            tau_ca=tau_ca, beta_ca=beta_ca, eps=eps, growth_rate=growth_rate))

        self.simulate()

        # check that we got the same values from one run to another
        # expected = self.se_nest[:, 10]
        # print(self.se_nest[:, 10].__repr__())
        expected = numpy.array([0.08374445370851626, 0.08374622771384878, 0.08372872162085436,
                                0.08377523830171477, 0.08376377406026522, 0.08377524732725673,
                                0.08375919233244447, 0.08371423280222919, 0.083725266553744,
                                0.08372601193476849])

        pop_as_list = list(self.pop)
        for n in self.pop:
            testing.assert_allclose(self.se_nest[pop_as_list.index(n), 10],
                                    expected[pop_as_list.index(n)],
                                    rtol=self.rtol,)

    def test_gaussian_growth_curve(self):
        beta_ca = 0.0001
        tau_ca = 10000.0
        growth_rate = 0.0001
        eta = 0.05
        eps = 0.10
        nest.SetStatus(
            self.pop,
            {
                'beta_Ca': beta_ca,
                'tau_Ca': tau_ca,
                'synaptic_elements': {
                    'se': {
                        'growth_curve': 'gaussian',
                        'growth_rate': growth_rate,
                        'eta': eta, 'eps': eps, 'z': 0.0
                    }
                }
            }
        )
        self.se_integrator.append(
            GaussianNumericSEI(tau_ca=tau_ca, beta_ca=beta_ca,
                               eta=eta, eps=eps, growth_rate=growth_rate))
        self.simulate()

        # check that we got the same values from one run to another
        # expected = self.se_nest[:, 30]
        # print(self.se_nest[:, 30].__repr__())
        expected = numpy.array([0.10036617553986826, 0.10056553185703253, 0.10040107765414216,
                                0.10029244040007103, 0.10052276942680986, 0.10041568803099227,
                                0.10040451902882779, 0.10052255715855712, 0.1006910528746381,
                                0.10058568067154924])

        pop_as_list = list(self.pop)
        for n in self.pop:
            testing.assert_allclose(self.se_nest[pop_as_list.index(n), 30],
                                    expected[pop_as_list.index(n)],
                                    rtol=self.rtol,)

    def test_sigmoid_growth_curve(self):
        beta_ca = 0.0001
        tau_ca = 10000.0
        growth_rate = 0.0001
        eps = 0.10
        psi = 0.10

        local_nodes = nest.GetLocalNodeCollection(self.pop)
        local_nodes.set(
            {
                'beta_Ca': beta_ca,
                'tau_Ca': tau_ca,
                'synaptic_elements': {
                    'se': {
                        'growth_curve': 'sigmoid',
                        'growth_rate': growth_rate,
                        'eps': eps, 'psi': 0.1, 'z': 0.0
                    }
                }
            })

        self.se_integrator.append(
            SigmoidNumericSEI(tau_ca=tau_ca, beta_ca=beta_ca,
                              eps=eps, psi=psi, growth_rate=growth_rate))
        self.simulate()

        # check that we got the same values from one run to another
        # expected = self.se_nest[:, 30]
        # print(self.se_nest[:, 30].__repr__())
        expected = numpy.array([0.07798757689720627, 0.07796809230928879, 0.07796745199672085,
                                0.07807166878406996, 0.07794925570454732, 0.0780381869323308,
                                0.0780054060483019, 0.0779518888224286, 0.07792681014092591,
                                0.07798540508673037])

        local_pop_as_list = list(local_nodes)
        for count, n in enumerate(self.pop):
            loc = self.se_nest[local_pop_as_list.index(n), 30]
            ex = expected[count]
            testing.assert_allclose(loc, ex, rtol=self.rtol)


def suite():
    test_suite = unittest.makeSuite(TestGrowthCurve, 'test')
    return test_suite


if __name__ == '__main__':
    unittest.main()
