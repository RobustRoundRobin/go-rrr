Robust Round Robin (RRR) Is a consensus algorithm adding fairness, liveness to
simple round robin leader selection. In return for accepting the use of stable
long term validator identities (node private keys), this approach scales to
10,000's of nodes.

The general approach is defined by this [paper](https://arxiv.org/pdf/1804.07391.pdf)

It is the intention of this work to provide a production grade implementation that is accepted
by upstream quorum as a PR.

We maintain a detailed description of the implementation approach 
[here](https://github.com/RobustRoundRobin/devclutter/blob/main/RRR-spec.md)
together with some tooling that may be useful for developers.

# TODO's and Status

A basic implementation is now complete and is suitable for development
experimentation and testing.

## Remaining items from the paper, required for production readines:

* [x] VRF's and proofs for seeding the random selection of endorsers
* [x] VRF seed initialisation
* [x] Allow the chain to progress if all Nc candidates in a round fail to
      seal a block. Currently one of the Nc candidates must seal a block in
      order for the chain to progress - as we have for convenience made round ==
      block. A round is triggered by a new chain head. And the Nc identities
      are only updated at the start of a round.
* [x] Exclude unresponsive nodes from selection - make idle
* [x] Re-enrolment of idle identities
* [x] Enrolement post genesis
* [ ] Respect --permissioned and --permissioned-nodes (this offers a form of identity removal)
* [ ] Wait Te rounds before considering a freshly enrolled identity 'active'.
      As a grinding attach mitigation for re-enrolment
* [ ] Full implementation of VerifyBranch
* [ ] Full implementation of SelectBranch

## Divergences from the paper

* [ ] The paper specifies that active identites are sorted by public key before
      being randomly sampled to select endorsers. In this implementation the
      identities are conveniently available 'pre' sorted by age. So we do not
      sort by public key.

## Items from the paper we have left out but would like to do:

* [ ] Mining of long term identities - without this (or SGX based identities)
      this implementation is only suitable for private networks.
* [ ] Multiple identity queues

## Things from the paper we do not intend (currently) to do:

* [ ] SGX based longterm identities

## General quality items we feel we must address:

* [ ] Unit test coverage to the standard of existing consensus implementations.
* [ ] The implementation currently maintains the active identities in a list.
      For networks with 1000's - 10,000's of active identities this will likely
      be inadequate.
* [ ] Independent review of implementation.
* [ ] Large scale and long term testing
