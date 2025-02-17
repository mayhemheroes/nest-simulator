.. _modelsmain:

Models in NEST
==============


What we mean by `models`
------------------------

Models in the context of NEST are C++ implementations of mathematical equations that describe the characteristics and behavior of
different types of neurons and synapses, based on the relevant peer-reviewed publications for the model.

We also use the term model in relation to network models (e.g., :doc:`microcircuit <../auto_examples/Potjans_2014/index>` and `multi-area model <https://inm-6.github.io/multi-area-model/>`_). These network models
can be considered a level of complexity higher than the neuron or synapse model. However, here, we focus on neuron and synapse models and not on network models.

Find a model
------------

NEST provides a ton of models! Textbook standards like integrate-and-fire and Hodgkin-Huxley-type models are available
alongside high-quality implementations of models published by the neuroscience community.
The model directory is organized and autogenerated by keywords (e.g., :doc:`adaptive threshold <index_adaptive threshold>`, :doc:`conductance-based <index_conductance-based>` etc.). 
Models that contain a specific keyword will be listed under that word.

.. seealso::

   Discover :doc:`all the models in our directory <index>`.

Create and customize models with NESTML
---------------------------------------

Check out :doc:`NESTML <nestml:index>`, a domain-specific language for neuron and synapse models.
NESTML enables fast prototyping of new models using an easy to understand, yet powerful syntax. This is achieved by a combination of a flexible processing toolchain
written in Python with high simulation performance through the automated generation of C++ code, suitable for use in NEST Simulator.

.. seealso::

  See the :doc:`NESTML docs for installation details <nestml:index>`.

.. note::

  NESTML is also available as part of NEST's official :ref:`docker image <docker>`.



Model naming
------------

Neuron models
~~~~~~~~~~~~~

Neuron model names in NEST combine abbreviations that describe the dynamics and synapse specifications for that model.
They may also include the author's name of a model based on a specific paper.

For example, the neuron model name

``iaf_cond_beta``

    corresponds to an implementation of a spiking neuron using integrate-and-fire dynamics with
    conductance-based synapses. Incoming spike events induce a postsynaptic change
    of conductance modeled by a beta function.

As an example for a neuron model name based on specific paper,

``hh_cond_exp_traub``


    implements a modified version of the Hodgkin Huxley neuron model based on Traub and Miles (1991)

Synapse models
~~~~~~~~~~~~~~

Synapse models include the word synapse as the last word in the model name.

Synapse models may begin with the author name (e.g., ``clopath_synapse``) or process (e.g., ``stdp_synapse``).

Devices
~~~~~~~

A device name should represent its physical counterpart - like a multimeter is ``multimeter``.  In general, the term ``recorder`` is used for devices
that store the output (e.g., spike times or synaptic strengths over time) of other nodes and make it accessible to the user. The term  ``generator`` is used for devices that provide input into the simulation.


.. seealso::

  See our glossary section on :ref:`common abbreviations used for model terms <model_terms>`. It includes alternative terms commonly used in the literature.

