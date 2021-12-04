Robust Round Robin (RRR) Is a consensus algorithm adding fairness, liveness to
simple round robin leader selection. In return for accepting the use of stable
long term validator identities (node private keys), this approach scales to
10,000's of nodes.

The general approach is defined by this [paper](https://arxiv.org/pdf/1804.07391.pdf)

[![Load test one configuration for each consensus alg ](https://github.com/RobustRoundRobin/go-rrr/actions/workflows/smoketest.yaml/badge.svg)](https://github.com/RobustRoundRobin/go-rrr/actions/workflows/smoketest.yaml)

# TODO's and Status

A basic implementation is now complete and is suitable for development
experimentation and testing.

* [ ] Respect --permissioned and --permissioned-nodes (this offers a form of identity removal)
* [ ] Wait Te rounds before considering a freshly enrolled identity 'active'.
      As a grinding attach mitigation for re-enrolment
* [ ] Full implementation of VerifyBranch
* [ ] Full implementation of SelectBranch

## Divergences from the paper

* The paper specifies that active identities are sorted by public key before
  being randomly sampled to select endorsers. In this implementation we provide
  (mostly for comparison) an additional approach: the identities are
  conveniently available 'pre' sorted by age. So we do not sort by public key.

## Items from the paper we have left out but would like to do:

* [ ] Mining of long term identities - without this (or SGX based identities)
      this implementation is only suitable for private networks.
* [ ] Multiple identity queues

## Things from the paper we do not intend (currently) to do:

* [ ] SGX based longterm identities
