# Authorized Wire Authenticated Key Exchange (AWAKE) Specification v0.1.0

## Editors

* [Brooklyn Zelenka](https://github.com/expede), [Fission](https://fission.codes)

## Authors

* [Brooklyn Zelenka](https://github.com/expede), [Fission](https://fission.codes)
* [Daniel Holmgren](https://github.com/dholms), [Bluesky](https://blueskyweb.xyz/)

# 0. Abstract

Authorized Wire Authenticated Key Exchange (AWAKE) is an [AKE](https://en.wikipedia.org/wiki/Authenticated_Key_Exchange) built on top of the [UCAN auth token](https://github.com/ucan-wg/spec). AWAKE is similar to other [mutual authentication](https://en.wikipedia.org/wiki/Mutual_authentication) schemes (such as self-signed [mTLS](https://datatracker.ietf.org/doc/html/rfc8705)), but with a focus on authorization and proof. AWAKE leverages the UCAN capability chain to prove access to some resource, validating that the requestor is communicating with a party capable of performing certain actions. This is a helpful root of trust with a well defined context when establishing a secure communications channel.

## Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

# 1 Introduction

AWAKE bootstraps a secure session on top of a public channel. Key exchanges for point-to-point communication are plentiful, but in open, trustless protocols, rooting trust can be a barrier for ad hoc communications channels. Two common approaches are to use a trusted certificate authority, or ignore the principal and "merely" establish a point-to-point channel.

Capability-based systems have a helpful philosophy towards a third path. By emphasizing authorization over authentication, they provide a way to know something provable about what the other party "can do", even if they have no sure way of knowing "who they are". One way of phrasing this is that such an agent is "functionally equivalent to the principal in this context". AWAKE makes use of authorization to bootstrap point-to-point sessions that are both secure and mutually trusted.

## 1.1 Terminology

This document contains shorthand (especially in diagrams) and nuanced senses of some terms. Below is a dictionary of AWAKE-specific terms:

| Term      | Meaning                                              |
| --------- | ---------------------------------------------------- |
| Attacker  | An attacker attempting to gain access to the channel |
| ECDH      | Elliptic Curve Diffie-Hellman                        |
| PK        | Public key                                           |
| Requestor | The agent opening the session                        |
| Responder | The agent being contacted by the Requestor           |
| SK        | Secret (private) key                                 |

## 1.2 Payload Fields

Payloads are encoding agnostic, but JSON is RECOMMENDED. For JSON, any fields that contain non-JSON values (such as ECDH public keys and encryption payloads) MUST be serialized as unpadded [Base64](https://datatracker.ietf.org/doc/html/rfc4648).

Messages that a peer cannot parse SHOULD be ignored.

All payloads MUST include the "AWAKE version" field `awv: "0.1.0"`. Payloads MUST also include a message type field `type` (see each stage for the value). All field keys and message type values MUST be lowercase and treated as case-sensitive.

| Field  | Value          | Description           | Required |
| ------ | -------------- | --------------------- | -------- |
| `awv`  | `"0.1.0"`      | AWAKE message version | Yes      |
| `type` | `awake/<type>` | AWAKE message type    | Yes      |

## 1.4 Encryption

Encryption is core to securing a tunnel. Key material and secrets created for AWAKE MUST be considered ephemeral and MUST NOT be reused between sessions.

At a high-level, AWAKE uses a NIST P-256 [Elliptic Curve Diffie-Hellman](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) (ECDH) [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/) to secure messages.

### 1.4.1 Asymmetric Keys

UCAN MUST be used as the signature envelope for AWAKE. Any UCAN-compatible asymmetric key MAY be used for signatures, including RSA, Ed25519, P-256, and so on.

The [ECDH portion](#1431-ecdh-input) of the [Double Ratchet KDF](#143-key-derivation) MUST use P-256.

### 1.4.2 Symmetric Keys

All symmetric encryption in AWAKE MUST use [256-bit AES-GCM](https://csrc.nist.gov/publications/detail/sp/800-38d/final). These keys MUST be derived from the [Double Ratchet](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey), and SHOULD be non-extractable where possible.

Each encrypted payload MUST include a unique (freshly generated) 12-byte [initialization vector](https://en.wikipedia.org/wiki/Initialization_vector).

### 1.4.3 Key Derivation

AWAKE uses a modified [Extended Triple Diffie-Hellman (X3DH)](https://www.signal.org/docs/specifications/x3dh/) protocol in order to support the WebCrypto API's non-extractable keys and make use of existing UCAN tokens without the need for pre-sharing keys.

Key derivation in AWAKE's double ratchet MUST use the following algorithm:

```
         Diffie-Hellman          Secret                               One-Time
            Ratchet               Chain                              Message Key
┌──────────────┴─────────────┐  ┌───┴───┐                           ┌────┴────┐
 
 Alice's P-256    Bob's P-256    Current
   Private Key    Public Key     Secret
            │      │                │
            │      │                │
       ┌────┼──────┼────────────────┼───────────────────────────┐
       │    │      │                │                           │
       │    │      │                │                           │
       │    ▼      ▼                ▼                           │
       │   ┌────────┐         ┌──────────┐                      │
       │   │        │         │          │                      │
       │   │  ECDH  ├────────►│  Concat  │                      │
       │   │        │         │          │                      │
       │   └────────┘         └─────┬────┘                      │
       │                            │                           │
       │                            │                           │
       │                            ▼                           │
       │                      ┌───────────┐     ┌───────────┐   │
       │                      │           │     │           │   │     256-bit
       │                      │  256-bit  ├────►│  256-bit  ├───┼───► AES Key
       │                      │    SHA3   │     │    SHA3   │   │      (OKM)
       │                      │           │     │           │   │
       │                      └─────┬─────┘     └───────────┘   │
       │                            │                           │
       │                            │                           │
       └────────────────────────────┼───────────────────────────┘
                                    │
                                    │
                                    ▼
                                  Next
                                 Secret
```

### 1.4.3.1 ECDH Input

The [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) secret MUST be generated using [NIST P-256 elliptic curve](https://neuromancer.sk/std/nist/P-256) curve (AKA `secp256r1`). Non-extractable P-256 keys SHOULD be used where available (e.g. via the [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey)).The sender MUST rotate their public key on every send. This does mean that in the [message phase](#4-secure-session), multiple keys MAY be valid due to concurrency and out-of-order message delivery. 

### 1.4.3.2 Secret Input

The secret chain MUST be update at each step by concatenating the secret generated at the previous step with the current ECDH output, and hashed with 256-bit SHA3. This new secret MUST be used as the input secret for the next message. Note that due to out-of-order message delivery, this secret MAY be used in up to one sent and one received message.

### 1.4.3.3 Output Message Key

The one-time message key MUST be unique for every message since one Diffie-Hellman key with have changed, and the secret is updated per send or receipt.

## 2 Sequence

AWAKE proceeds in one connection step, four communication rounds, and an OPTIONAL disconnection:

1. Both parties subscribe to a well-known channel
2. Requestor broadcasts intent
    * a. Temporary DID
    * b. Responder authorization criteria
3. Responder establishes point-to-point session
    * a. Responder securely proves that they have sufficient rights
    * b. Responder transmits a session key via asymmetric key exchange
4. Requestor authentication
    * a. Requestor sends actual DID
    * b. Requestor sends instance validation (e.g. UCAN or out-of-band PIN)
5. Responder sends an `ACK`
6. Secure session messages (zero or more rounds)
7. Either party disconnects

```
Attacker                 Requestor                  Responder
   │                         │                          │      ─┐
   │       Temp ECDH DID     │      Temp ECDH DID       │ (2a)  │
   │      & Auth Criteria    │     & Auth Criteria      │ (2b)  │
   │◄────────────────────────┼─────────────────────────►│       │
   │                         │                          │       │
   │                         │       Authorization      │ (3a)  │
   │                         │       & Secret Init      │ (3b)  │
   │                         │◄─────────────────────────┤       │
   │                         │                          │       ├─ Handshake
   │                         │        Actual DID        │ (4a)  │
   │                         │        & Challenge       │ (4b)  │
   │                         ├─────────────────────────►│       │
   │                         │                          │       │
   │                         │                          │       │
   │                         │           ACK            │ (5)   │
   │                         │◄─────────────────────────┤       │
   │                         │                          │      ─┘
   ϟ                         ϟ                          ϟ      ─┐
   │                         │                          │       │
   │                         │         Messages         │ (6)   ├─ Session
   │                         │◄────────────────────────►│       │
   │                         │                          │       │ 
   ϟ                         ϟ                          ϟ      ─┘
   │                         │                          │      ─┐
   │                         │           FIN            │ (7)   │
   │                         │◄────────────────────────►│       ├─ Disconnection
   │                         │                          │       │
   │                         ▀                          ▀      ─┘
```
    
# 3. Handshake

## 3.1 Subscribe to Common Channel

AWAKE begins by all parties listening on a common channel. AWAKE itself is channel and transport agnostic; it MAY be broadcast to all listeners, MAY be asynchronous, and MAY be over any transport. To reduce channel noise, it is RECOMMENDED that this channel be scoped to a specific topic.

For instance, a WebSocket pubsub channel on the topic `awake:did:key:zStEZpzSMtTt9k2vszgvCwF4fLQQSyA15W5AQ4z3AR6Bx4eFJ5crJFbuGxKmbma4` MAY be used for messages about resources owned by `did:key:zStEZpzSMtTt9k2vszgvCwF4fLQQSyA15W5AQ4z3AR6Bx4eFJ5crJFbuGxKmbma4`.

The AWAKE handshake MUST occur on a single channel. The underlying channel MAY be changed after the handshake is complete.

## 3.2 Requestor Broadcasts Intent

**NOTE: This stage is completely in the clear.**

```
Attacker                 Requestor                  Responder
   │                         │                          │ 
   │      Temp ECDH DID      │     Temp ECDH DID        │ (1a)
   │     & Auth Criteria     │    & Auth Criteria       │ (1b)
   │◄────────────────────────┼─────────────────────────►│
   ⋮                         ⋮                          ⋮
```

In this step, the Requestor broadcasts a temporary DID, and some criteria that a Responder MUST provide in [§3.3](https://github.com/ucan-wg/awake/blob/port/README.md#33-responder-establishes-point-to-point-session). Both pieces of information are sent in a single message. This request payload MUST contain the `did` and `caps` fields. The `caps` field MAY be an empty array.

The payload stage MUST be signalled by the message type `"awake/init"`.

### 3.2.1 Temporary ECDH DID

Since this message is sent entirely in the clear, the Requestor MUST generate a fresh P-256 key pair per AWAKE initialization attempt. This key MUST be used as the first step in the ECDH Double Ratchet. In the payload, the public key MUST be formatted as a [did:key](https://w3c-ccg.github.io/did-method-key/#p-256).

This temporary key MUST only be used for key exchange, and MUST NOT be used for signatures, and MUST NOT be persisted past this one session bootstrap (i.e. discard after [§3.3](#33-responder-establishes-point-to-point-session)). It is RECOMMENDED that the private key be non-extractable when possible, such as via the [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey).
    
### 3.2.2 Authorization Criteria

The Requestor MAY also include validation criteria expected from the Responder. This MUST be passed as an array of [UCAN capabilities](https://github.com/ucan-wg/spec#23-capability). The Responder MUST be able to prove access to these capabilities in [§3.3](https://github.com/ucan-wg/awake/blob/port/README.md#33-responder-establishes-point-to-point-session).

### 3.2.3 Payload

| Field  | Value          | Description                                    | Required |
| ------ | -------------- | ---------------------------------------------- | -------- |
| `awv`  | `"0.1.0"`      | AWAKE message version                          | Yes      |
| `type` | `"awake/init"` | Signal which step of AWAKE this payload is for | Yes      |
| `did`  |                | The Requestor's initial (temp) ECDH P-256      | Yes      |
| `caps` |                | Capabilities that the Responder MUST provide   | Yes      |

#### 3.2.3.1 JSON Example

``` javascript
{
  "awv": "0.1.0",
  "type": "awake/init",
  "did": "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv",
  "caps": [
    {
      "with": "mailto:me@example.com",
      "can": "msg/send"
    },
    {
      "with": "dns:example.com",
      "can": "crud/update"
    },
    {
      "with": "owned://did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp/*",
      "can": "*"
    }
  ]
}
```

## 3.3 Responder Establishes Point-to-Point Session

**NOTE: The Responder is not yet trusted at this step, and MUST be treated as a possible impersonator or [PITM](https://en.wikipedia.org/wiki/Man-in-the-middle_attack)**

```
Requestor                  Responder
    ⋮                          ⋮
    │       Authorization      │ (3a)
    │       & Secret Init      │ (3b)
    │◄─────────────────────────┤
    ⋮                          ⋮
```

In this step, the Responder MUST prove that they have access to the requested resources. This is used to establish trust in the capabilities of the Responder, but MUST NOT actually delegate anything. This UCAN MUST contain the Requestor's temporary ECDH DID in the `aud` field. The `iss` field MUST contain the Responder's actual DID (i.e. not a temporary ECDH DID).

This step starts the Double Ratchet. The Responder MUST generate a fresh ECDH P-256 key pair. This MUST be combined with the Requestor's ECDH public key to generate a 256-bit AES key, which MUST be used to encrypt the private payload. The Requestor SHOULD accept multiple concurrent connection attempts on this request DID, at least until the handshake is complete.

The payload contains two encryption layers, and signature: the ECDH components, the AES envelope, and the capability proof signed by the Responder's "true" DID.

The SHA3 hash of the AES key generated in this step MUST be used as the first [input secret in the KDF](#1432-secret-input).

```
          Payload

     ┌──────ECDH─────┐
     │               │
     │  256-bit AES  │
     │       │       │
     └───────┼───────┘
             │
             ▼
┌─────────AES-GCM─────────┐
│                         │
│  ┌────────UCAN───────┐  │
│  │                   │  │
│  │  iss: Responder   │  │
│  │  aud: ReqECDH     │  │
│  │  att: []          │  │
│  │  fct: nextResECDH │  │
│  │  prf: ...         │  │
│  │                   │  │
│  └───────────────────┘  │
│                         │
└─────────────────────────┘
```

Upon receipt, the Requestor MUST validate that the UCAN capabilities fulfill their `caps` criteria. The UCAN itself MUST be valid, unrevoked, unexpired, and intended for the temporary DID (the `aud` field). If any of these checks fail, the session MUST be abandoned, the temporary DID regenerated, and the protocol restarted from [intention broadcast](#32-requestor-broadcasts-intent).

### 3.3.1 Validation UCAN

The validation UCAN MUST NOT be used to delegate any capabilities. This UCAN MUST only be used to prove access to capabilities and sign the AES key. The `att` and `my` fields MUST be empty arrays. The issuer (`iss`) field MUST contain the Responder's long-term DID (rather than the temporary ECDH DID). The audience (`aud`) field MUST contain the Requestor's temporary ECDH DID from [§3.2](#32-requestor-broadcasts-intent).

This UCAN MUST be encrypted with the [KDF-generated AES-GCM key](#143-key-derivation) plus IV before being placed into the payload in [§3.3.2](#332-payload).

#### 3.3.1.1 Challenge

The Responder MUST set the method of challenge to validate the Requestor. This MUST be set in the `fct` section of the UCAN so that it is signed by the Responder. The RECOMMENDED authorization methods are out-of-band PIN validation (`oob-pin`) and UCAN (`ucan`).

To set the challenge as `oob-pin`, the `fct` section of the UCAN MUST include the following:

``` javascript
{
  ...,
  "fct": [
    ...,
    {"awake/challenge": "oob-pin"}
  ]
}
```

To set the challenge as `ucan`, the `fct` section of the UCAN MUST include the following:

``` javascript
{
  ...,
  "fct": [
    ...,
    { 
      "awake/challenge": "ucan",
      "caps": [...requiredCaps] 
    }
  ]
}
```

If more than one `awake/challenge` field is set, the lowest-indexed one MUST be used.

#### 3.3.1.2 Next Responder ECDH

The UCAN's facts (`fct`) field MUST also include the next Responder ECDH public key (to be used in Step 4) encoded as `did:key`. Having the next key in the UCAN places it inside the signature envelope, associating the next key with the Responder's UCAN DID.

``` javascript
//JSON encoded
{
  ...,
  "fct": [
    ...,
    {"awake/nextdid": step4EcdhDid}
  ]
}
```

If more than one `awake/nextdid` field is set, the lowest-indexed one MUST be used.

### 3.3.2 Payload

To start the Double Ratchet, the payload in this stage has the highest number of cleartext fields. Note that the value in the `res` field contain the temporary ECDH DIDs, and MUST NOT use the Responder's actual long-term DID. Conversely, the UCAN inside the encrypted payload MUST use the Responder's long-term DID.

| Field  | Value         | Description                                                                              | Required |
| ------ | ------------- | ---------------------------------------------------------------------------------------- | -------- |
| `awv`  | `"0.1.0"`     | AWAKE message version                                                                    | Yes      |
| `type` | `"awake/res"` | "Responder's Auth" step message type                                                     | Yes      |
| `iss`  |               | Responder's ECDH P-256 DID                                                               | Yes      |
| `aud`  |               | The ECDH P-256 DID signalled by the Requestor in [§3.2](#32-requestor-broadcasts-intent) | Yes      | 
| `iv`   |               | Initialization vector for the encrypted `auth` payload                                   | Yes      |
| `msg`  |               | AES-GCM-encrypted validation UCAN                                                        | Yes      |

#### 3.3.3.1 JSON Example

``` javascript
{
  "awv": "0.1.0",
  "type": "awake/res",
  "iss": responderStep3EcdhDid,
  "aud": requestorStep2EcdhDid,
  "iv": iv,
  "msg": encryptedUcan 
}
```

## 3.4. Requestor Challenge

**NOTE: The Requestor is not yet trusted at this step, and MUST be treated as a possible impersonator or PITM**

```
Requestor                  Responder
    ⋮                          ⋮
    │        Actual DID        │ (4a)
    │        & Challenge       │ (4b)
    ├─────────────────────────►│
    ⋮                          ⋮
```

At this stage, the Responder has been validated, but the Requestor is still untrusted. The Requestor now MUST provide their actual DID over the secure channel, and MUST prove that they are a trusted party rather than a PITM, eavesdropper, or phisher. This is accomplished in a single message.

The Requestor MUST provide the proof of authorization set by the Responder payload in [§3.3.2](#332-validation-ucan). The RECOMMENDED authorization methods are PIN validation (`pin`) and UCAN (`ucan`). Note that if the Requestor does not know how to respond to fulfill an authorization method, the AWAKE connection MUST fail with an [`unknown-challenge` message](#62-unknown-challenge-type).

### 3.4.1 Payload

This message MUST be encrypted with the first AES output of the AWAKE [KDF](#143-key-derivation), using the initial chain secret established in [§3.3](#33-responder-establishes-point-to-point-session).

| Field  | Value                                       | Description                                                      | Required |
| ------ | ------------------------------------------- | ---------------------------------------------------------------- | -------- |
| `awv`  | `"0.1.0"`                                   | AWAKE message version                                            | Yes      |
| `type` | `"awake/msg"`                               | Generic AWAKE message type                                       | Yes      |
| `id`   | `sha3_256(reqStep2EcdhPk + resStep3EcdhPk)` | Message ID                                                       | Yes      |
| `iv`   |                                             | Initialization vector for the encrypted payload                  | Yes      |
| `msg`  |                                             | Fulfilled challenge payload encrypted with AES key from KDF step | Yes      |

``` javascript
{
  "awv": "0.1.0",
  "type": "awake/msg",
  "id": sha3_256(reqStep2EcdhPk + resStep3EcdhPk),
  "iv": iv,
  "msg": encryptedChallenge
}
```

#### 3.4.2.2 Out-of-Band PIN Challenge

Out-of-band PIN challenges are most useful when the Requestor would not be able to provide UCAN validation, such as when signing into a new device that has not been delegated to yet. The PIN MUST be set by the Responder, and transmitted out of band. Some examples of out of band transmission include displaying text on screen, email, text message, or QR code.

The PIN values MUST be within the UTF-8 character set. The PIN MUST be included in the `pin` field. It is RECOMMENDED that the PIN be restricted to human-readable characters, and 4 to 10 characters long. If a very long challenge is required, it is RECOMMENDED that the SHA3 hash of the challenge be used rather than putting a large challenge over the wire.

| Field  | Value                                                      | Description                 | Required |
| ------ | ---------------------------------------------------------- | --------------------------- | -------- |
| `did`  |                                                            | "Actual" Requestor DID      | Yes      |
| `sig`  | `sign(requestorPK, sha3_256(responderDid + outOfBandPin))` | Signature of challenge hash | Yes      |

```javascript
{
  "did": requestorActualDid,
  "sig": signedHash
}
```

#### 3.4.2.3 Direct UCAN Challenge

If UCAN auth is required by the Responder, the Requestor MUST provide a UCAN. This is the same strategy as the one used by the Responder in [§3.3](#33-responder-es tablishes-point-to-point-session): the UCAN MUST be encrypted with the session key and the IV from the enclosing payload, MUST be given in a raw format, and MUST be inline (without a JSON object wrapper or similar).

The UCAN MUST be issued (`iss`) by the Requestor's DID (not the temporary DID), and its audience (`aud`) MUST be the Responder's DID. The `att` field MUST be set to an empty array (i.e. it MUST NOT delegate any capabilities). The `prf` array MUST fulfill the capabilities set by the Responder.

```
              UCAN Auth

┌──────────────AES-GCM────────────┐
│                                 │
│  ┌────────────UCAN───────────┐  │
│  │                           │  │
│  │  iss: RequestorActualDid  │  │
│  │  aud: ResponderActualDid  │  │
│  │  fct: nextReqECDH         │  │
│  │  att: []                  │  │
│  │  prf: ...                 │  │
│  │                           │  │
│  └───────────────────────────┘  │
│                                 │
└─────────────────────────────────┘
```

# 3.5 Responder Acknowledgment

The Responder MUST respond with an acknowledgment that the challenge in [§3.4](#34-requestor-challenge) was accepted.

```
Requestor                  Responder
    ⋮                          ⋮
    │           ACK            │ (5)
    │◄─────────────────────────┤
    │                          │
```

### 3.5.1 Payload

| Field  | Value                             | Description                                                    | Required |
| ------ | --------------------------------- | -------------------------------------------------------------- | -------- |
| `awv`  | `"0.1.0"`                         | AWAKE message version                                          | Yes      |
| `type` | `"awake/msg"`                     | Generic AWAKE message type                                     | Yes      |
| `id`   | `sha3_256(resEcdhPk + reqEcdhPk)` | Message ID                                                     | Yes      |
| `iv`   |                                   | Initialization vector for the encrypted payload                | Yes      |
| `msg`  |                                   | Fulfilled challenge payload encrypted with Step 4 ECDH AES-key | Yes      |

#### 3.5.1.1 Encrypted Message

The encrypted message payload MUST include an `awake/ack` field, with a value of the requestor's long-term DID. This payload MAY contain additional fields. This is often useful if dovetailing the ACK with the first message of a session using the 

``` javascript
{
  ...,
  "awake/ack": reqActualDid
}
```

## 4 Secure Session

```
Requestor                  Responder
    ⋮                          ⋮
    │                          │
    │         Messages         │ (6)
    │◄────────────────────────►│
    │                          │
    ⋮                          ⋮
```

Messages sent over an established AWAKE session MUST contain the following keys:
 
| Field  | Value                                                 | Description                                                             | Required |
| ------ | ----------------------------------------------------- | ----------------------------------------------------------------------- | -------- |
| `awv`  | `"0.1.0"`                                             | AWAKE message version                                                   | Yes      |
| `type` | `"awake/msg"`                                         | Generic AWAKE message type                                              | Yes      |
| `mid`  | `sha3_256(latestSenderEcdhPk + latestReceiverEcdhPk)` | Message ID                                                              | Yes      |
| `sid`  | `sha3_256(firstSecret)`                               | OPTIONAL session ID                                                     | No       |
| `iv`   |                                                       | Initialization vector for the encrypted payload                         | Yes      |
| `msg`  |                                                       | Fulfilled challenge payload encrypted with latest ECDH AES-key          | Yes      |
| `esig` | `encrypt(messageKey, sig(senderUcanSk, msg + mid))`   | OPTIONAL message signature using the sender's UCAN-validated public key | No       |

The OPTIONAL encrypted signature field (`esig`) MAY be included to prove authenticity of the payload. Without this field, an eavesdropper with access to the input secret MAY be able to spoof a message that updates the next ECDH key to one it controls. The signature MUST be encrypted, since some commonly used key types such as RSA allow for the derivation of the signer's public key.

Additional cleartext keys MAY be used, but are NOT RECOMMENDED since they can leak information about your session or the payload. Encrypted payloads MAY be padded with random noise or broken across multiple messages to prevent certain kinds of metadata leakage.

### 4.1 Encrypted Field Keys

Every encrypted payload (`msg`) MUST include a `awake/nextdid` field, updating the public key of the sender for the next message(s). This continues the Double Ratchet and updates the AES key that will be used for successive messages.

Additional fields MAY be included to contain further payload.

| Field           | Description                                                          | Required |
| --------------- | -------------------------------------------------------------------- | -------- |
| `awake/nextdid` | The next ECDH public key for the sender, formatted as a `did:key`    | Yes      |

``` javascript
// JSON encoded
{
  ...,
  "awake/nextdid": sendersNextEcdhDid
}
```

## 4.3 Message ID

Since every message's KDF has at least one unique ECDH key, and at most two messages MAY use the same secret in a strict order, the message sequence number is uniquely determined by the latest exchanged ECDH public keys. The exact format MUST be the 256-bit SHA3 of the sender and receiver's ECDH public keys.

``` javascript
msgId = sha3_256(latestSenderEcdhPk + latestReceiverEcdhPk)
```

The recipient SHOULD calculate the next possible message IDs, based on known keys. Unless a synchronous protocol is being explicitly used, some number of previous keys SHOULD be considered active to receive out-of-order messages. The recipient SHOULD store messages that it cannot match message IDs for.

To protect against a Byzantine peer flooding its connections with a large number of keys, it is RECOMMENDED that the keys have a TTL, be stored in a fixed-size LIFO queue, or both.

## 4.2 Session ID

As out-of-order messages can lead to a large number of messages, an OPTIONAL session ID based on the SHA3 hash of the first input secret (`sha3_256(sah3_256(first_ecdh))`) MAY be used during the message phase of AWAKE, but moving to a message channel (such as a unique pubsub topic) is RECOMMENDED as it provides the same function with less noise.

# 5 Disconnection

```
Requestor                  Responder
    ⋮                          ⋮
    │                          │
    │           FIN            │ (7)
    │◄────────────────────────►│
    │                          │
    ▀                          ▀ 
```

Graceful disconnection from an AWAKE attempt can be broadcast at any step with the following payload:
 
| Field  | Value                                                 | Description                                                    | Required |
| ------ | ----------------------------------------------------- | -------------------------------------------------------------- | -------- |
| `awv`  | `"0.1.0"`                                             | AWAKE message version                                          | Yes      |
| `type` | `"awake/msg"`                                         | Generic AWAKE message type                                     | Yes      |
| `mid`  | `sha3_256(latestSenderEcdhPk + latestReceiverEcdhPk)` | Message ID                                                     | Yes      |
| `sid`  | `sha3_256(firstSecret)`                               | OPTIONAL session ID                                            | No       |
| `iv`   |                                                       | Initialization vector for the encrypted payload                | Yes      |

This message MAY be broadcast at any time during an AWAKE session, including to cancel the AWAKE handshake attempt. This payload SHOULD NOT contain any other keys.

### 5.1 Encrypted Field Keys

The disconnection message MUST include an `awake/fin` key with `disconnect` for its value. It MAY include additional fields.

| Field       | Value        | Description             | Required |
| ----------- | ------------ | ----------------------- | -------- |
| `awake/fin` | `disconnect` | Disconnection directive | Yes      |

``` javascript
// JSON encoded
{
  ...,
  "awake/fin": "disconnect"
}
```

# 6 Errors

### 6.1 Cleartext Envelope

All errors MUST use the generic AWAKE message format, and include the error in the encrypted payload. It MUST use the latest ECDH keys.

| Field  | Value                                   | Description                                                    | Required |
| ------ | --------------------------------------- | -------------------------------------------------------------- | -------- |
| `awv`  | `"0.1.0"`                               | AWAKE message version                                          | Yes      |
| `type` | `"awake/msg"`                           | Generic AWAKE message type                                     | Yes      |
| `id`   | `sha3_256(latestEcdhPk + latestEcdhPk)` | Message ID                                                     | Yes      |
| `iv`   |                                         | Initialization vector for the encrypted payload                | Yes      |
| `msg`  |                                         | Fulfilled challenge payload encrypted with Step 4 ECDH AES-key | Yes      |

## 6.2 Unknown Challenge Type

| Field         | Value               | Description                         | Required |
| ------------- | ------------------- | ----------------------------------- | -------- |
| `awake/error` | `unknown-challenge` | Unknown challenge type              | Yes      |
| `awake/id`    |                     | Message ID that generated the error | Yes      |

``` javascript
// JSON encoded
{
  "awake/error": "unknown-challenge",
  "awake/id": offendingMessageId
}
```

# 7 Prior Art

## 7.1 Mutual TLS (mTLS)

[mTLS](https://www.rfc-editor.org/rfc/rfc8705.html) is the best-known mutual authentication protocol. In many ways, AWAKE is mTLS with trusted rooted in UCAN and a self-signed capabilities model.

## 7.2 IKEv2

The [Internet Key Exchange (IKE) Protocol](https://datatracker.ietf.org/doc/html/rfc7296) is typically (but not exclusively) used as part of [IPsec](https://en.wikipedia.org/wiki/IPsec). IKE generally uses certificate authorities (CAs). IKE requires that X.509 be supported.

IKE shares many commonalities with AWAKE, including making available of the same cryptographic algorithms (e.g. P-256).

## 7.3 WireGuard

[WireGuard](https://www.wireguard.com/) is a VPN protocol that is widely deployed via the Linux kernel, and has since been ported to many other systems. It is UDP-based and aimed at raw performance and security. Being so level, is unconstrained in which cryptographic primitives is uses (i.e. Curve25519).

## 7.4 Message Layer Security (MLS)

[MLS](https://messaginglayersecurity.rocks/) is a work-in-progress protocol that aims to eventually improve on TLS 1.3. It includes design considerations for doing group messaging, uses ratchet trees, and so on. MLS does include the ability to use certificate authentication (among other authentication methods).

AWAKE may adopt MLS features in the future as it becomes more mature, but today AWAKE is restricted to a point-to-point protocol.

## 7.5 Signal Protocol

The [Signal Protocol](https://github.com/signalapp/libsignal) influenced the design of AWAKE. Signal is extremely widely deployed, having been included in WhatsApp, Android Messages, the Signal app, and others.

Signal's deployment targets have complete control over their cryptographic stack, and makes use of algorithms like 3XDH based on Curve25519. The AWAKE threat model includes browser application security that requires non-extractable keys, and at time of writing very few of these primitives are available.

