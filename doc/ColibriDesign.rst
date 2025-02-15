**************
COLIBRI Design
**************


About This Document
===================
COLIBRI is a quality-of-service (QoS) system for SCION. This brief design
document is based on the thesis by Dominik Roos entitled "COLIBRI: A
Cooperative Lightweight Inter-domain Bandwidth Reservation Infrastructure".
In this document, we will explain the core ideas of COLIBRI and the differences
from that thesis.

This document will briefly discuss how the COLIBRI packets are forwarded,
and how the same type of COLIBRI packets are used to transport the
control-plane traffic.
This document will dig deeper in the COLIBRI service itself and give a more
detailed view of the operations it will perform for the control plane
to work.


Components
==========
There are five main components that need to be modified or created: the
COLIBRI service itself, the border router, a monitoring system, and
``sciond`` in the end host:

COLIBRI Service
    Enables the COLIBRI control plane. Used to negotiate both segment and
    end-to-end reservations.

Border Router
    Needs to process COLIBRI packets differently than SCION packets and forward
    the COLIBRI traffic with higher priority than best effort.

Stamping Service
    The data-plane packets originating from the end-host go through
    the stamping service of their AS, before they are forwarded to
    the next on-path AS of the reservation. The *stamping service*
    computes the per packet MAC that is later validated in the border routers
    of the remaining on-path ASes.

Monitoring
    Does the accounting and policing. It monitors per flow packets when
    originating in this AS, or stateless when they are only transit.

sciond
    Needs to expose a COLIBRI *API*. Needs to manage end-to-end reservations on
    behalf of the applications.


Data & Control-Plane Transport
==============================
Nomenclature:

Reservation version
    For any reservation (whether segment or end-to-end, see below) to be used,
    it is necessary to have one (and only one) active version.
    The version **cannot** make a modification to the path of a reservation.
    However, it can modify the reserved bandwidth, as well as other
    properties of the reservation.

Segment reservation
    A reservation between two ASes. This is a "tube" that allows to communicate
    control-plane traffic directly, or to embed one or multiple end-to-end
    reservations inside.
    All segment reservations have a maximum set of 16 versions.

End-to-end (E2E) reservation
    A reservation between two end hosts. It is used to send data traffic. It
    uses from one to three segment reservations to reach the destination end
    host (similar to regular SCION paths). The E2E reservation "stitches" these
    segment reservations to create a valid E2E reservation.
    An E2E reservation has a maximum set of 16 versions.

Reservation ID
    Segment and E2E reservations have a reservation ID. It uniquely identifies
    the reservation.
    Both segment and E2E reservation IDs contain the AS ID of the reservation
    originator AS as the first 6 bytes, and then a suffix of 4 bytes in the
    case of a segment ID, or 12 bytes in the case of an E2E one::

      ReservationID = AS ID || Suffix

   The suffix spanning 4 and 12 bytes, for segment and E2E reservations
   respectively, has enough space to avoid clashes by incrementing the suffix
   in the case of segment reservations, or by randomly choosing one,
   in the case of an E2E reservation.

There is only one type of COLIBRI packet. It is mainly used by the data plane
to transport user data in E2E reservations between end-host machines.
But this COLIBRI packet is also used by the COLIBRI service when it needs to
transport requests and responses between COLIBRI services in different ASes.
The advantage of this decision is the simplicity of the treatment of the
COLIBRI packets in the border router.

Design Requirements
-------------------
#. The monitoring system computes the bandwidth usage per E2E reservation.
   The monitoring system must be able to catch E2E reservations over-usage and
   double usage with high probability, without keeping any state.
#. The border router must validate and forward the packets very quickly.
   For this, as mentioned before, we have only one COLIBRI packet type,
   and no hop-by-hop extensions. This means that the control-plane traffic
   uses the same transport mechanism.
#. The border router must be able to check the validity of each packet without
   keeping state, or keeping it to a very small set of private keys.

Design Decisions
----------------
According to the requirements described above, here are some of the decisions
taken to fulfill them:

#. Monitoring is only necessary for E2E reservations.
   The monitoring system will simply ignore the segment reservations.
   A version of an E2E reservation is valid until its expiration time,
   thus the validity of a reservation is always consistent in both
   data and control planes.
#. A COLIBRI path is composed of one mandatory timestamp, one *InfoField* and
   a sequence of *HopFields*.
   This applies to both segment and E2E reservations. The
   *InfoField* controls what the border router can do with the packet:

   - Each COLIBRI packet can be used as if it had a hop-by-hop extension
     inside. This allows control traffic, which must always stop at each
     COLIBRI service, to be sent using COLIBRI packets.
     This is done via a ``Control (C)`` flag.
     These packets are always delivered to the local COLIBRI anycast address
     by the border router.
   - Each packet distinguishes the type of reservation via a flag in its
     *InfoField*. This allows a packet to have either a segment or an E2E
     reservation. This is the ``Segment (S)`` flag. It forces the ``C`` to
     be also set (only control traffic is allowed on segment reservations).
   - A COLIBRI packet can reverse its path, via the ``Reverse (R)`` flag.
     Via this flag, we can always send the responses to the requests that
     the COLIBRI services receive. The responses always travel in the
     reverse direction, and must always stop at each COLIBRI service
     on the path.
     For control plane traffic, the bandwidth is also guaranteed when
     ``R=1``. Data plane traffic going in the reverse direction will
     be treated as best-effort traffic.

.. Note::

   As also data plane traffic can traverse a COLIBRI path in the
   reverse direction, this allows the destination host to directly
   send back an answer without having to fetch a new path to the
   source. It furthermore enables border routers to reply with SCMP
   messages in case of a forwarding failure.
   *This decision to allow reverse data plane traffic is tentative:
   we need to check whether it is actually the best solution to allow
   for those use cases.*

#. The cryptographic tag enabling packet validation for an AS relies only on a
   private key derived from secret AS values (e.g., the master key), and fields
   present in the packet.

.. Note::

   To enable high speed processing of the COLIBRI packets,
   we keep the fields in a fixed well-known position.
   This applies for instance to the existence of the timestamp for COLIBRI
   packets of a segment reservation (where the timestamp is not needed),
   or the length of the ID suffix (which could be shorter
   for segment reservations).


.. _colibri-mac-computation:

MAC Computation
---------------
A message-authentication code (MAC) is used in the validation of a packet when
it is being forwarded.
It protects the path in the following ways:

- Values of the InfoField and HopFields cannot be altered.
- HopFields must be used in the right order they were provided.
  I.e., a HopField that was obtained in a path as the `i`-th one,
  must always be used in the `i`-th position.
- The number of HopFields is unaltered.
- The source of the traffic is authenticated for E2E data-plane traffic
  (so that the monitor system knows which source AS to attribute traffic to).

To achieve the protection we want against changes in the relevant parts
of the *InfoField* and *HopField*, we will include the following in the
MAC computation (and call them the *InputData* for the MAC computation):

- Reservation ID: as each HopField's MAC is bound to the unique
  reservation ID, it is impossible to "splice" reservations, i.e.,
  combine HopFields from multiple reservations. Therefore, the
  MAC chaining employed in standard SCION is not needed
  (note that an ID is bound to exactly one path).
- Reservation fields: fields that came from the reservation setup, and that
  should not be altered otherwise, must be included in the MAC computation.
  This prevents malicious clients from tampering with the reservation and
  claiming more reserved bandwidth than what they were granted.
  These fields are:

  - Expiration time (reservation expiration tick).
  - Granted bandwidth.
  - Request latency class.
  - Version number.

- Other fields of the *InfoField* related to the path that should
  not be altered:

  - The ``C`` flag.

- Finally the ingress and egress interface IDs of the particular AS computing
  the MAC.

.. Note::
    Setting any of ``R`` or ``S`` to 1 forces ``C=1``.
    This way a COLIBRI packet with ``C=1`` will traverse the COLIBRI service
    of each AS on the path, and these COLIBRI services can
    (and possibly will) check that the ingress/egress pair
    they observe in their HopField corresponds to
    that stored in their DB for the reservation ID of the packet.

To calculate the MAC we will use a secret only known to :math:`\text{AS}_i`,
denoted as :math:`K_i`. This secret can be the same one as the one used
to compute the MAC in the normal SCION packet.

We calculate the MAC differently depending on the value of the flag ``C``.
For ``C=1`` the MAC is first computed by each of the on-path ASes,
very similarly to the regular SCION path case.
Each HopField of the path needs a MAC that is computed by
exactly one on-path AS (the owner of the HopField) who then sets it in the MAC
field of the HopField.
Later, like with the regular SCION path,
this MAC field is validated by the same on-path AS when a packet
enters one of its border routers.
Note that every on-path AS is able to observe the HopFields of all
the other on-path ASes, and could leak them if they wanted to,
rendering this mechanism useless to authenticate the source of the packet.

With ``C=0`` (data plane traffic), we want to avoid end hosts
from the source of the reservation AS *A*,
and any other on-path ASes, to be able to leak the MACs to
other entities in different ASes, that could then generate traffic
that appears like generated from the original AS *A*, and thus have AS *A*
been wrongly blamed for consuming more than their granted bandwidth,
which would surely have it blacklisted in the transit ASes.
To do this we will use a per-packet MAC computation approach.
This is done by computing a different type of MAC:
the *per-packet* MAC.
Note that ``C=0`` is only possible for E2E reservations not doing any
control-plane operation, as setting any ``R`` or ``S`` forces ``C`` to be set.

Let's call *A* the source of the reservation, and *B* an
AS in the path of said reservation. :math:`K_B` is a secret key that only
*B* knows. *MAC* is the function used to compute the MAC. *InputData* are
all the fields specified above, that will be part of the MAC computation.
Let's describe both MACs. The **static MAC** is used as a mechanism to
validate each HopField when ``C=1``:

.. math::
    \text{MAC}_B^{C=1} \equiv \text{MAC}_{K_B}(InputData)

With ``C=0``, the **per-packet MAC** has to be computed.
We denote the per-packet MACs as *HVF* (hop-validation field),
which uses :math:`\sigma_B` as key a value very similar to the static MAC defined
above, but with ``C=0`` and also using the source and destination host
addresses from the address header:

.. math::
    \begin{align}
    \sigma_B &= \text{MAC}_B^{C=0}\\
    \sigma_B &= \text{MAC}_{K_B}(InputData, DT, DL, ST, SL, SrcHost, DstHost)\\
    \end{align}

With:

SL, DL
    Source and Destination host addresses lengths.

ST, DT
    Source and Destination host addresses types.

We then introduce a high-precision time stamp of each packet, *PacketTimestamp*.
This time stamp is further defined in the SCION header document
(the value of HVF changes with each E2E COLIBRI packet, even when
:math:`\sigma_B` does not).
The (HVF) is computed as follows:

.. math::
    \text{HVF}_B &= \text{MAC}_{\sigma_B}(\text{PacketTimestamp},
    \text{Original Payload Length}) \\

Note that the key used to compute the HVF is :math:`\sigma_B`, the static
MAC computed by *B*, which is only known to *B* and *A*.
The *Original Payload Length* is the same as the PayloadLen from the
SCION common header in case of ``R=0``. For ``R=1`` it does not contain
the packet length of the (response) packet, but still the packet length
of the original packet (which went in the forward direction). This
allows to verify the HVF also for backwards COLIBRI data plane traffic.

The MAC values when ``C=1`` are communicated in the successful response
of a segment or E2E reservation setup or renewal,
without any type of encryption.
In the same response message, we
add each of the :math:`\sigma_B` for each AS *B* part of the path, but
encrypted only for *A*, e.g. using DRKey.
The AS *A* will store both the static :math:`\text{MAC}_X^{C=1}`
as well as the :math:`\sigma_B` values, that will be used as keys in the
per-packet MAC computation.

For the sake of simplicity let's say that this computation happens in a
specific service only for this purpose, that receives COLIBRI traffic from
the local end hosts, checks their permissions, and then computes the HVF
that go in the packet.

If, at a later moment, the HVF computed for a packet while in transit
at *B* is correct, *B* knows that only *A* could have actually computed it,
since the :math:`\sigma_B` was not ever given to end hosts, but only
to the *official* service of AS *A*.


Control-Plane General Overview
==============================
Because the ``C`` flag makes a COLIBRI packet to stop at every COLIBRI
service along the reservation path, the requests can be sent
using a normal COLIBRI packet with ``C=1``. The responses will be sent
by the COLIBRI service using ``C=1`` and ``R=1``. This applies for both
segment and E2E reservation operations, and thus depending on the type,
the flag ``S`` will be set or not.

This delivery mechanism cannot be abused, as every border router must check
that if any of the ``R`` or ``S`` flags are set, ``C`` is also set. And
if ``C`` is set, the border router must deliver the packet
to the local COLIBRI service.
The COLIBRI service checks the source validity on each operation via
DRKey tags inside the payload, that authenticate that the source is
indeed requesting this operation.

Since all control-plane operations have ``C=1``, they use the static MAC.

E2E Reservation Renewal Operation
---------------------------------
For convenience, we provide the trace of an E2E reservation renewal. This
example has the following values:

- Reservation originator: end host :math:`h_1` in AS *A*
- Reservation destination: end host :math:`h_2` in AS *G*
- The reservation stitches 3 segment reservations:

  - Up: :math:`A \rightarrow B \rightarrow C`.
  - Core: :math:`C \rightarrow D \rightarrow E`.
  - Down: :math:`E \rightarrow F \rightarrow G`.

#. The host :math:`h_1` in *A* decides to renew the reservation. For this it
   sends a request to the COLIBRI service at *A*.
   The packet has its path with flags :math:`\verb!C=1,R=0,S=0!`,
   and HopFields for
   :math:`A \rightarrow B \rightarrow C \rightarrow D
   \rightarrow E \rightarrow F \rightarrow G`.
#. The COLIBRI service at *A* handles the request. It does the admission
   in *A*. It adds the maximum bandwidth from the admission to the
   request and sends a message to the next hop, which is *B*.
   All the static MACs :math:`\text{MAC}_X^{C=1}` were provided in
   a previous setup of the reservation and stored in the service.
#. The border router at *A* forwards the packet to *B*
#. The border router at *B* validates its HopField. It is correct.
   The ``C`` flag is set, so the border router delivers
   the packet to the COLIBRI service.
#. The COLIBRI service at *B* handles the request and does the admission.
   It is admitted and the payload is modified accordingly.
   The COLIBRI service sends the message to the next hop, which is C.
#. The process continues on this way until there is an error or the request
   reaches the last AS `G`.

   - If there is an error, the payload is modified, and
     the message is sent in reverse. This means ``R=1,C=1``.
     The hop fields in the packet are reversed, as well as the source and
     destination AS from the address header.
     The packet will traverse the path in reverse until it reaches `A`, where
     it will be finally forwarded to :math:`h_1`, the reservation originator.
   - If there are no errors, the request will reach AS `G`. There the
     admission is computed in the COLIBRI service, and it will be forwarded
     to the destination end host :math:`h_2`. The end host will decide the
     admission of the reservation and respond to its AS's COLIBRI service.

#. Assuming the request was admitted all the way up to the destination end-
   host :math:`h_2`, this will reverse the traversal of the path by setting
   ``R=1,C=1`` and send it to its AS's COLIBRI service.
#. The COLIBRI service at `G` receives the response
   stating that the renewal was accepted, and then
   it adds the HopField to the payload. It also computes both MACs
   :math:`\text{MAC}_G^{C=1}` and :math:`\text{MAC}_G^{C=0}` (which is
   :math:`\sigma_G`) and encrypts and authenticates the latter with
   :math:`DRKey K_{G \to A}`. Both MACs are
   also added to the payload. The packet is sent to the border router at `G`.
#. The border router at `G` receives the COLIBRI packet with ``R=1,C=1``,
   and forwards it to the next border router, at `F`.
#. The border router at `F` receives the packet. It checks whether the MAC
   is valid and drops the packet if not. If the MAC is
   valid (:math:`\text{MAC}_F^{C=1}` is independent of the ``R`` flag),
   the border router delivers it to the local COLIBRI service.
#. The COLIBRI service at `F` now adds its own HopField and
   the two MACs :math:`\text{MAC}_F^{C=1}` and :math:`\sigma_F`,
   the latter encrypted with :math:`DRKey K_{F \to A}`.
   It then sends it to the border router.
#. The process continues until the packet reaches the COLIBRI service at `A`,
   where the HopFields inside are decrypted and stored so that COLIBRI
   traffic originating for this reservation can be correctly stamped with the
   appropriate MAC value.

Core-Segment Renewal Operation
------------------------------
The segment reservation operations look very much like in the previous example,
with the peculiarity of having the ``S=1`` flag.
This example covers the renewal of a core-segment reservation traversing
the ASes in the sequence :math:`C \to D \to E`.
These are the steps:

#. The COLIBRI service at `C` decides to renew the core-segment reservation.
   The path of the reservation has the flags and HopFields:
   :math:`\verb!C=1,R=0,S=1!, C \to D \to E`. The COLIBRI service at
   `C` does the initial AS admission and sends the request to the
   local border router.
#. The border router at `C` sees the packet with ``C=1`` incoming via its
   local interface. It will validate the packet and forward it to the next
   border router, at `D`.
#. The border router at `D` receives the packet via the remote interface with
   `C`. It validates the MAC successfully, as well as the rest of the fields.
   Since ``C=1`` it delivers it to the local COLIBRI service.
#. The COLIBRI service at `D` computes the admission, and
   updates the request with the admission values. It then sends
   the packet to the border router again, to be forwarded.
#. Similarly to the previous steps, the packet finally arrives to the local
   COLIBRI service at `E`. It does the admission and, since this
   is the last AS in the path, it adds its HopField and
   :math:`\text{MAC}_E^{C=1}`
   to the payload and it switches direction by setting ``R=1``.
   Now the packet is sent back to the border router to be forwarded to the
   next hop.
#. The packet is now traveling in the reverse direction of the reservation,
   and arrives to the border router at `D`. This border router validates the
   packet and sends it to the local COLIBRI service.
#. The COLIBRI service at `D` receives the packet and adjusts in its DB the
   values for the reservation. It adds its HopField and the two MACs and
   sends the packet again to the border router, to continue its journey.
#. The packet arrives to the border router at `C`, and since it has the flag
   ``C=1`` it delivers it to the local COLIBRI service, after validating that
   the MAC and the rest of the fields are okay.
#. Finally, the COLIBRI service at `C` receives the packet and stores the
   HopFields and MACs from the payload.

Down-Segment Renewal Operation
------------------------------
It is of special interest to check the case of a down-segment
reservation renewal, as it has to originate in what would later be
the destination AS. E.g. if the core AS is `E`, and the path
consists of the sequence :math:`E \rightarrow F \rightarrow G`,
the COLIBRI service at `G` triggers the operation by requesting the
COLIBRI service at `E` to send the initial request along the path.
These are the steps:

#. The COLIBRI service at `G` decides it is time to renew a down-segment
   reservation that ends at `G`. It prepares a trigger request and
   sends it along the path, with the flag ``R=1``.
#. The trigger request travels along the reservation, stopping at each
   COLIBRI service, but not being processed until it reaches its recipient,
   which is the COLIBRI service at `E`.
#. The COLIBRI service at `E` handles the trigger request. It checks
   (like with all control plane operations) the authenticity of the
   request source, in this case with :math:`DRKey K_{E \to G}`.
#. After authenticating the source, it proceeds to trigger a segment
   reservation renewal. These steps are enumerated e.g. in
   `core-segment renewal operation`_.

Segment Reservation First Setup
-------------------------------
When there is no previous reservation possible to reach each and all of the
on-path ASes necessary to establish a segment reservation setup,
best effort traffic must be used.

E2E Reservation First Setup
---------------------------
When there is no previous E2E reservation that could be used to reach each
and all of the on-path ASes of a desired E2E reservation, the endhost still has
the possibility of sending the request to its local COLIBRI service,
always specifying which (up to three) segment reservations to stitch
to build the E2E reservation. The COLIBRI service will transport the request,
and the subsequent response, using segment reservations.

#. The endhost sends an E2E reservation setup request to its local
   COLIBRI service.
#. The COLIBRI service of the reservation source AS will proceed with the
   setup process as usual, with the only difference that it will send the
   request to the next on-path AS using the first segment reservation.
#. Each of the on-path ASes receive the request, which is being transported
   using a segment reservation.
#. The COLIBRI service at the transfer ASes will change the segment reservation
   to forward the request with, using the next segment reservation.
#. The COLIBRI service at the last transfer AS may have to use a down-segment
   to send the request to the next COLIBRI service. This is still possible,
   as this COLIBRI service also has the appropriate HopFields to use that
   down-segment reservation (see `Setup a Segment Reservation`_ below).
#. The rest of the process continues similarly to what is depicted on
   `E2E Reservation Renewal Operation`_.


COLIBRI Service
===============
The COLIBRI Service manages the reservation process of the COLIBRI QoS
subsystem in SCION. It handles both the segment and E2E reservations
(formerly known as steady and ephemeral reservations).

The COLIBRI service is structured similarly to
other existing Go infrastructure services. It reuses the following:

- `go/lib/env`: Is used for configuration and setup of the service.
- `go/pkg/trust`: Is used for crypto material.
- `go/lib/infra`: Is used for the messenger to send and receive messages.
- `go/lib/periodic`: Is used for periodic tasks.

The COLIBRI service is differentiated into these parts:

* **configuration** specifying admission and reservation parameters for this AS,
* **handlers** to handle incoming reservation requests (creation,
  tear down, etc.),
* **periodic tasks** for segment reservation creation and renewal,
* **reservation storage** for partial and committed reservations.

.. image:: fig/colibri/COS.png


Operations for Segment Reservations
-----------------------------------
In general, all the requests travel from :math:`\text{AS}_i`
to :math:`\text{AS}_{i+1}`, where :math:`\text{AS}_{i+1}` is the next AS
to :math:`\text{AS}_i` in the direction of the reservation.

Responses travel in the reverse direction: from :math:`\text{AS}_{i+1}` to
:math:`\text{AS}_i`.

The exception to this are the down-segment reservations.
The down-segment reservation requests travel (with ``R=1``) from the
reservation destination to the reservation initial AS
(:math:`\text{AS}_n \to \text{AS}_{n-1} \to \ldots \text{AS}_0`).
This is done this way because the operation initiator will always be the
reservation destination.
So in a setup :math:`A \leftarrow B \leftarrow C`
where `A` is the final destination of the reservation,
it will also be `A` the AS to initiate the setup/renewal process,
by sending a request using an existing reservation (if it exists) and ``R=1``.
The same reasoning applies to the responses, that travel from
:math:`\text{AS}_i` to :math:`\text{AS}_{i+1}`.
In the example above, they would travel from `C` to `A`, with ``R=0``.

Setup a Segment Reservation
***************************
The configuration specifies which segment reservations should be created from
this AS to other ASes. Whenever that configuration changes, the service
should be notified.

#. The service triggers the creation of a new segment reservation at
   boot time and whenever the segment reservation configuration file changes.
#. The service reads the configuration file and creates a segment reservation
   request per each entry.

   - The path used in the request must be obtained using the *path predicate*
     in the configuration.

#. The store in the COLIBRI service saves the intermediate request and
   sends the request to the next AS in the path.
#. If there is a timeout, this store will send a cleanup request to the
   next AS in the path.
#. Otherwise a response will arrive before the timeout. If it is a failure,
   it gets reported in the logs. A new attempt of a setup is triggered.
#. If the response is successful, there will be a set of MACs in the
   the response, only for ``C=1`` (segment reservations are always
   ``C=1,S=1``). These MACs are stored alongside with the HopFields in the DB
   for this reservation, and the setup finishes.
#. If the response was successful and the segment reservation is of type
   down-segment (checkeable in the service via the COLIBRI store),
   the reservation initiator (which is the requester) will inform the
   reservation origin (which is the core AS) with the HopFields and MACs
   necessary to send packets from there to here.
   This is so that the E2E reservation setups (that sometimes travel in
   segment reservations when there are no previous E2E reservations) can
   travel inside a down-segment reservation.

Renew a Segment Reservation
***************************
#. The service triggers the renewal of the existing segment reservations
   with constant frequency.
#. The store in the COLIBRI service retrieves each one of the reservations
   that originate in this AS.
#. Per reservation retrieved, the store adds a new version to it and
   pushes it forward, with the same dynamics as in
   `Setup a Segment Reservation`_.

Handle a Setup Request
**********************
#. The COLIBRI service store is queried to admit the segment reservation.
#. The store decides the admission for the reservation (how much bandwidth).
   It uses the *traffic_matrix* from the configuration package.
#. The store saves an intermediate reservation entry in the DB.
#. If this AS is the last one in the path, the COLIBRI service store saves the
   reservation as final and notifies the previous AS in the path with a
   reservation response.
#. The store forwards the request with the decided bandwidth.

Handle a Renewal Request
************************
The renewal request handler is the same as the `handle a setup request`_.
The renewal is initiated differently (by adding a new version to an existing
reservation), but handled the same way.

Handle a Setup Response
***********************
#. If the response is a failure, it gets reported in the logs.
#. If the response is successful, the store saves the reservation as final.
   It also adds the HopField and its MAC for ``C=1`` to the response.
#. The store sends the response back in the direction it was already traveling
   (possibly with ``R=1`` unless this is a down-segment reservation).
#. If this AS is the first one in the reservation path (aka
   *reservation initiator*), the store also starts
   an version confirmation request.

Handle an Version Confirmation Request
**************************************
#. The store in the COLIBRI service checks that the appropriate reservation
   is already final.
#. The store modifies the reservation to be confirmed
#. The COLIBRI service forwards the confirmation request.

Handle a Cleanup Request
************************
#. The COLIBRI service removes the referenced reservation from its store.
#. The COLIBRI service forwards the cleanup request.

Handle a Teardown Request
*************************
#. The COLIBRI service checks the reservation is confirmed but has no
   allocated E2E reservations.
#. The COLIBRI service checks there are no telescoped reservations using
   this segment reservation.
#. The store removes the reservation.
#. The COLIBRI service forwards the teardown request.

Handle a Reservation Query
**************************
#. The store in the COLIBRI service receives the query and returns the
   collection of segment reservations matching it.

Operations for E2E Reservations
-------------------------------

Handle an E2E Setup Request
***************************
#. The COLIBRI service queries the store to admit the reservation
#. The store computes the allowed bandwidth (knowing the current segment
   reservation and the existing E2E reservations in it).
#. The store pushes forward the setup request, successful or otherwise.

Handle an E2E Setup Response
****************************
#. The COLIBRI service receives a response traveling in the opposite direction
   as the request.
#. This COLIBRI service computes the maximum bandwidth it would be willing
   to grant, and adds this information to the response.
#. If the response was and still is successful after its own admission,
   the service adds its HopField and two sets of MACs to the response (the
   two sets are for ``C=0`` and ``C=1``).
#. The response is sent along its way.
#. If this was the COLIBRI service at the *reservation initiator* AS, the
   COLIBRI service decrypts the ``C=0`` MACs and sends them to the
   *stamping service* (the service in charge of computing the per packet MACs
   or *HVFs*) if the response was successful, and informs in any case of
   the result to the originating end-host of the reservation.

Handle an E2E Renewal Request
*****************************
The renewal request handler is the same as the `handle an e2e setup request`_.

Handle an E2E Cleanup Request
*****************************
#. The COLIBRI service removes the request from its store.
#. The COLIBRI service forwards the cleanup request.

Interfaces of the COLIBRI Service
---------------------------------
Main interfaces of the service.

The Reservation Store in the COLIBRI service keeps track of the reservations
created and accepted in this AS, both segment and E2E.
The store provides the following interface:

.. code-block:: go

    type ReservationStore {
        GetSegmentReservation(ctx context.Context, id SegmentReservationID) (SegmentReservation, error)
        GetSegmentReservations(ctx context.Context, validTime time.Time, path []InterfaceId]) ([]SegmentReservation, error)

        AdmitSegmentReservation(ctx context.Context, req SegmentReservationReq) error
        ConfirmSegmentReservation(ctx context.Context, id SegmentReservationID) error
        CleanupSegmentReservation(ctx context.Context, id SegmentReservationID) error
        TearDownSegmentReservation(ctx context.Context, id SegmentReservationID) error

        AdmitE2EReservation(ctx context.Context, req E2EReservationReq) error
        CleanupE2EReservation(ctx context.Context, id E2EReservationID) error
    }

The `sciond` end-host daemon will expose the *API* that enables the use
of COLIBRI by applications:

.. code-block:: go

    type sciond {
        ...
        AllowIPNet(ia IA, net IPNet) error
        BlockIPNet(ia IA, net IPNet) error
        WatchSegmentRsv(ctx context.Context, pathConf PathConfiguration) (WatchState, error)
        WatchE2ERsv(ctx context.Context, resvConf E2EResvConfiguration) (WatchState, error)
        // WatchRequests returns a WatchState that will notify the application of any COLIBRI e2e request ending here.
        WatchRequests() (WatchState, error)
        Unwatch(watchState WatchState) error
    }

Reservation DB
--------------
There are two main parts in the DB: the segment reservation entities, and the
end-to-end entities.
To link the E2E reservations to the appropriate segment ones,
a table is used.

There are no restrictions of cardinality other than uniqueness and non
null-ness for some fields, but nothing like triggers on insertion are used.
E.g. it is technically possible to link more than three segment reservations
with a given E2E one. These cardinality restrictions are enforced
by code.

.. image:: fig/colibri/DB.png

Furthermore, there are some indices created to speed up lookups:

* seg_reservation
    * id_as,suffix
    * ingress
    * egress
    * path
* seg_version
    * reservation,version_number
* e2e_reservation
    * reservation_id
* e2e_version
    * reservation,version_number
* e2e_to_seg
    * e2e
    * seg
