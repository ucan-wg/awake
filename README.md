# Authorized Wire Authenticated Key Exchange (AWAKE) Specification v0.1.0

## Editors

* [Brooklyn Zelenka](https://github.com/expede), [Fission](https://fission.codes)

## Authors

* [Brooklyn Zelenka](https://github.com/expede), [Fission](https://fission.codes)
* [Daniel Holmgren](https://github.com/dholms), [Bluesky](https://blueskyweb.xyz/)

# 0. Abstract

Authorized Wire Authenticated Key Exchange (AWAKE) is an [AKE](https://en.wikipedia.org/wiki/Authenticated_Key_Exchange) built on top of the [UCAN auth token](https://github.com/ucan-wg/spec). AWAKE is similar to other mutual authentication schemes, such as self-signed [mTLS](https://datatracker.ietf.org/doc/html/rfc8705), but with a focus on authorization proofs. AWAKE leverages the capability chain to prove access to some resource, validating that the requestor is communicating with a party capable of performing certain actions. This is a helpful root of trust with a well defined context when establishing a secure communications channel.

The core problem that AWAKE solves is bootstrapping a secure session on top of a public channel. Key exchanges for point-to-point communication are plentiful, but in open, trusteless protocols, rooting trust can be a barrier for ad hoc communications channels. Two common approaches are to use a trusted certificate authority, or ignore the principal and "merely" establish a point-to-point channel.

Capability-based systems have a helpful philosophy towards a third path. By emphasizing authorization over authentication, they provide a way to know something provable about what the other party "can do", even if they have no sure way of knowing "who they are". One way of phrasing this is that such an agent is "functionally equivalent to the principal in this context".

## Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

# 1 Introduction

## 1.1 Payload Fields

All payloads MUST include the "AWAKE Version" field `awv: "0.1.0"`. Payloads MUST also include a message type field `type` (see each stage for the value). All field keys and message type values MUST be case-insensitive.

| Field  | Value          | Description           | Required |
| ------ | -------------- | --------------------- | -------- |
| `awv`  | `"0.1.0"`      | AWAKE message version | Yes      |
| `type` | `awake/<type>` | Step message type     | Yes      |

## 1.2 Roles

| Name      | Role                                                 |
| --------- | ---------------------------------------------------- |
| Requestor | The agent opening the session                        |
| Responder | The agent being contacted by the Requestor           |
| Attacker  | An attacker attempting to gain access to the channel |

## 2 Sequence

AWAKE proceeds in one connecion step and four communication rounds:

1. Both parties subscribe to a well-known channel
2. Requestor broadcasts intent
    * a. Temporary DID
    * b. Responder authorization criterea
3. Responder establishes point-to-point session
    * a. Responder securely proves that they have sufficient rights
    * b. Responder transmits a session key via asymmetric key exchange
4. Requestor authentication
    * a. Requestor sends actual DID
    * b. Requestor sends instance validation (e.g. UCAN or out-of-band PIN)
5. Responder sends an `ACK`

```
Attacker                 Requestor                  Responder
   │                         │                          │ 
   │        Temp DID  &      │        Temp DID &        │ (2a)
   │       Auth Criterea     │      Auth Criterea       │ (2b)
   │◄────────────────────────┼─────────────────────────►│
   │                         │                          │
   │                         │       Authorization      │ (3a)
   │                         │       & Session Key      │ (3b)
   │                         │◄─────────────────────────┤
   │                         │                          │
   │                         │        Actual DID        │ (4a)
   │                         │        & Challenge       │ (4b)
   │                         ├─────────────────────────►│
   │                         │                          │
   │                         │                          │
   │                         │           ACK            │ (5)
   │                         │◄─────────────────────────┤
   │                         │                          │
```

# 3. Detailed Stages

## 3.1 Subscribe to Common Channel

AWAKE begins by all parties listening on a common channel. The channel itself is unimportant: it MAY be public, broadcast to all listeners, be assynchronous, and over any transport. To reduce channel noise, it is RECOMMENDED that this channel be specific to some topic. For instance, a websocket channel on the topic`awake:did:key:zStEZpzSMtTt9k2vszgvCwF4fLQQSyA15W5AQ4z3AR6Bx4eFJ5crJFbuGxKmbma4` MAY be used for messages about resources owned by `did:key:zStEZpzSMtTt9k2vszgvCwF4fLQQSyA15W5AQ4z3AR6Bx4eFJ5crJFbuGxKmbma4`.

Graceful disconnection from an AWAKE attempt can be broadcast at any step with the following payload:

``` javascript
{
  "awake": "fin", 
  "did": requestorTrueOrTempDid
}
```

## 3.2 Requestor Broadcasts Intent

**NOTE: This stage is completely in the clear.**

```
Attacker                 Requestor                  Responder
   │                         │                          │ 
   │        Temp DID  &      │        Temp DID &        │ (1a)
   │       Auth Criterea     │      Auth Criterea       │ (1b)
   │◄────────────────────────┼─────────────────────────►│
   ⋮                         ⋮                          ⋮
```

In this step, the Requestor broadcasts a temporary DID, and some criterea that it extects a Responder to provide. Both pieces of information are sent in a single message. This request payload MUST contain the `did` and `caps` fields. The `caps` field MAY be an empty array.

The payload stage MUST be signalled by the pair `"awake": "init"`.

### 3.2.1 Temporary DID

The Requestor generates a fresh 2048-bit [RSA-OAEP](https://datatracker.ietf.org/doc/html/rfc3447) key pair. This key pair MUST be referenced as a [`did:key`](https://w3c-ccg.github.io/did-method-key/) in the payload.

This "temporary DID", and MUST only be used for key exchange. It MUST NOT be used for signatures, and MUST NOT be persisted past this one session boostrap (i.e. discard after [Step 3](#33-responder-establishes-point-to-point-session)).

### 3.2.2 Authorization Criterea

The Requestor MAY also include validation criterea expected from the Responder. This MUST be passed as an array of [UCAN capabilities](https://github.com/ucan-wg/spec#23-capability). The Responder will have to prove access to these capabilties.

### 3.2.3 Payload

| Field   | Value          | Description                                          | Required |
| --------| -------------- | ---------------------------------------------------- | -------- |
| `awv`   | `"0.1.0"`      | AWAKE message version                                | Yes      |
| `type`  | `"awake/init"` | Signal which step of AWAKE this payload is for       | Yes      |
| `did`   |                | The DID of the Requestor this is intended for        | Yes      |
| `caps`  |                | Capabilities that the Responder MUST provide         | Yes      |

#### 3.2.3.1 JSON Example

``` javascript
{
  "awv": "0.1.0",
  "type": "awake/init"
  "did": "did:key:z4MXj1wBzi9jUstyPMS4jQqB6KdJaiatPkAtVtGc6bQEQEEsKTic4G7Rou3iBf9vPmT5dbkm9qsZsuVNjq8HCuW1w24nhBFGkRE4cd2Uf2tfrB3N7h4mnyPp1BF3ZttHTYv3DLUPi1zMdkULiow3M1GfXkoC6DoxDUm1jmN6GBj22SjVsr6dxezRVQc7aj9TxE7JLbMH1wh5X3kA58H3DFW8rnYMakFGbca5CB2Jf6CnGQZmL7o5uJAdTwXfy2iiiyPxXEGerMhHwhjTA1mKYobyk2CpeEcmvynADfNZ5MBvcCS7m3XkFCMNUYBS9NQ3fze6vMSUPsNa6GVYmKx2x6JrdEjCk3qRMMmyjnjCMfR4pXbRMZa3i",
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
      "with": "as:did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp:*",
      "can": "*"
    }
  ]
}
```

## 3.3 Responder Establishes Point-to-Point Session

**NOTE: The Responder is not yet trusted at this step, and MUST be treated as a possible impersonator or PITM**

```
Requestor                  Responder
    ⋮                          ⋮
    │       Authorization      │ (3a)
    │       & Session Key      │ (3b)
    │◄─────────────────────────┤
    ⋮                          ⋮
```

In this step, the Responder MUST prove that they have access to the requested resources, and sets up a protected point-to-point connection. This is used to establish trust in the capabilities of the Responder, but MUST NOT actually delegating anything.

The temporary RSA key from the previous step MUST be exclusively used for exchanging a 256-bit AES-GCM "session key". RSA is both slow and can only hold a limited number of bytes, so using it to encrypt the payloads of the rest of the session is infeasable.

The payload contains two encryption layers, and signature: the RSA envelope, the AES envelope, and the AES key signed by the Responder.

```
          Payload

        ┌───RSA───┐
        │         │
        │ AES-GCM │
        │    │    │
        └────┼────┘
             │
             │
             ▼
┌─────────AES-GCM────────┐
│                        │
│  ┌───────UCAN───────┐  │
│  │                  │  │
│  │  iss: Responder  │  │
│  │  aud: TempDID    │  │
│  │  fct: AES-GCM    │  │
│  │  att: []         │  │
│  │  prf: ...        │  │
│  │                  │  │
│  └──────────────────┘  │
│                        │
└────────────────────────┘
```

Upon receipt, the Requestor MUST validate that the UCAN capabilities fulfill their `caps` criterea. The UCAN itself MUST be valid, unrevoked, unexpired, and intended for the temporary DID (the `aud` field). If any of these checks fail, the session MUST be abandoned, the temporary DID regenerated, and the protocol restarted from [intention braodcast](#32-requestor-broadcasts-intent).

### 3.3.1 Key Exchange

The Responder MUST generate a fresh 256-bit AES-GCM key and 12-byte initialization vector (IV) per connection request. It is RECOMMENDED that the Responder track all DIDs requested with, and to only respond to each temporary DID exactly once.

The key used in this step MUST be used as input key material (IKM) to derive keys in rest of the AWAKE bootstrap. The AES key MUST be encoded as padded base64 and included in the facts (`fct`) section of the payload UCAN. The rest of the [validation UCAN is constructed](#332-validation-ucan) and signed per normal, thus including the AES key in the signature payload. This signature serves as proof that the AES key was intended for this specific session.

``` javascript
{
  fct: [
    {
      "awake/ikm": base64PaddedIkm,
    }
  ]
}
```

The entire UCAN MUST be encrypted with the same AES-GCM key as included in the facts section, and using the IV before being added to the payload.

The IV MUST be generated fresh for every message in this session. If the session is not fully established, the AES key MUST NOT ever be reused.

FIXME add section about KDF in the intro

### 3.3.2 Validation UCAN

The validation UCAN MUST NOT be used to delegate any capabilities. This UCAN MUST only be used to prove access to capabilities and sign the AES key. The `att` and `my` fields MUST be empty arrays.

#### 3.3.2.1 Challenge

The Responder MUST set the method of challege to validate the Requestor. This MUST be set in the `fct` section of the UCAN so that it is signed by the Responder. The RECOMMENDED authorization methods are out-of-band PIN validation (`oob-pin`) and UCAN (`ucan`).

To set the challenge as `oob-pin`, the `fct` section of the UCAN MUST include the following:

``` javascript
{
  ...,
  "fct": [
    {"awake/challenge": "oob-pin"}
  ]
}
```

To set the challenge as `ucan`, the `fct` section of the UCAN MUST include the following:

``` javascript
{
  ...,
  "fct": [
    { 
      "awake/challenge": "ucan",
      "caps": [...requiredCaps] 
    }
  ]
}
```

### 3.3.3 Payload

| Field  | Value               | Description                                                           | Required |
| ------ | ------------------- | --------------------------------------------------------------------- | -------- |
| `awv`  | `"0.1.0"`           | AWAKE message version                                                 | Yes      |
| `type` | `"awake/res"`       | "Responder's Auth" step message type                                  | Yes      |
| `aud`  | `sha3_256(tempDid)` | 256-bit SHA3 hash of the Requestor temp DID                           | Yes      |
| `ikm`  |                     | An RSA-encrypted IKM (initial AES) used to encrypt the `auth` payload | Yes      |
| `iv`   |                     | Initialization vector for the encrypted `auth` payload                | Yes      |
| `auth` |                     | AES-GCM-encrypted validation UCAN, encoded as base64-padded           | Yes      |

#### 3.3.3.1 JSON Example

``` javascript
{
  "awv": "0.1.0",
  "type": "awake/res",
  "aud": sha3_256(requestorTempDid),
  "ikm": encyptedSessionIKM,
  "iv": iv,
  "auth": encryptedUcan 
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

FIXME change the key to treat the session key as a KDF

This message MUST be encrypted with the key derived from `sha3_256(+ sessionKey)` -- FIXME note the hash chain in the introduction section! 

At this stage, the Responder has been validated, but the Requestor is still untrusted. The Requestor now MUST provide their actual DID over the secure channel, and MUST prove that they are a trusted party rather than a PITM, evesdropper, or phisher. This is accomplished in a single message.

The Requestor MUST provide the proof of authorization set in the Responder payload in s3.3.2 (FIXME). The RECOMMENDED authorization methods are PIN validation (`pin`) and UCAN (`ucan`). Note that if the Requestor does not know how to respond to fulfill an authorization method, the AWAKE connection MUST fail with a `type: "awake/error/unknownauthtype"` FIXME define message type

### 3.4.2 Key Derivation

The key used to encrypt this message MUST be the 256-bit SHA3 of the IKM from Step 3.3 (FIXME) prefixed by "awake/req"

``` javascript
reqStepKey = sha3_256("awake/req" + base64PaddedIkm)
```

### 3.4.2 Payload

| Field  | Value                       | Description                                                | Required |
| ------ | --------------------------- | ------------------------------------------------------ | -------- |
| `awv`  | `"0.1.0"`                   | AWAKE message version                                  | Yes      |
| `type` | `"awake/req"`               | "Requestor Auth" message type                          | Yes      |
| `id`   | `sha3_256(resDid + aesKey)` | The session ID                                         | Yes      |
| `iv`   |                             | Initialization vector for the encrypted `ucan` payload | Yes      |
| `auth` |                             | Encrypted challenge encoded as base64-padded           | Yes      |

The challenge MUST be encrypted with the session key and IV from the enclosing payload.

FIXME open question: should the type be hidden?

``` javascript
{
  "awv": "0.1.0",
  "type": "awake/req",
  "id": sha3_256(reqStepKey),
  "iv": iv,
  "auth": encryptedChallenge
}
```

#### 3.4.2.2 Out-of-Band PIN Challenge

Out-of-band PIN challenges are most useful when the Requestor would not be able to provide UCAN validation, such as when signing into a new device that has not been delegated to yet. The PIN MUST be set by the Responder, and transmitted out of band. Some examples of out of band transmission include displaying text on screen, email, text message, or QR code.

The PIN values MUST be within the UTF-8 character set. The PIN MUST be encoded as base64-padded in the `pin` field. It is RECOMMENDED that the PIN be restricted to human-readable characters, and 4 to 10 characters long. If a very long challenge is required, it is RECOMMENDED that the SHA3 hash of the challenge be used rather than putting a large challenge over the wire.

This challenge MUST be encrypted with the session key and IV from the enclosing payload.

| Field  | Value                                                                    | Description                               | Required |
| ------ | ------------------------------------------------------------------------ | ----------------------------------------- | -------- |
| `did`  |                                                                          | "Actual" Requestor DID                    | Yes      |
| `sig`  | `base64Padded(sign(responderPK, sha3_256(responderDid + outOfBandPin)))` | Base64-padded signature of challenge hash | Yes      |

```javascript
{
  "did": requestorDid,
  "sig": signedHash
}
```

#### 3.4.2.3 Direct UCAN Challenge

If UCAN auth is required by the Responder, the Requestor MUST provide a UCAN. This is the same strategy as the one used by the Responder in s3.3 (FIXME): the UCAN MUST be encrypted with the session key and the IV from the encosing payload, MUST be given in a raw format (not further base64 encoded), and MUST be inline (without a JSON object wrapper or similar). The encrypted value MUST be encoded as base64-padded.

The UCAN MUST be issued (`iss`) by the Requestor's DID (not the temporary DID), and its audience (`aud`) MUST be the Responder's DID. The `att` field MUST be set to an empty array (i.e. it MUST NOT delegate any capabilities). The `prf` array MUST fulfill the capabilities set by the Responder.

```
         UCAN Auth

┌─────────AES-GCM────────┐
│                        │
│  ┌───────UCAN───────┐  │
│  │                  │  │
│  │  iss: Requestor  │  │
│  │  aud: Responder  │  │
│  │  fct: AES-GCM    │  │
│  │  att: []         │  │
│  │  prf: ...        │  │
│  │                  │  │
│  └──────────────────┘  │
│                        │
└────────────────────────┘
```

# 3.5 Responder Acknowledgment

The Responder MUST respond with an acknowledgement that the challenge in Step 4 (FIXME) was accepted.

```
Requestor                  Responder
    ⋮                          ⋮
    │           ACK            │ (5)
    │◄─────────────────────────┤
    │                          │
```

### 3.5.1 Key Derivation

The key used to encrypt this message MUST be the 256-bit SHA3 of the IKM from Step 3.3 (FIXME) prefixed by "awake/req"

``` javascript
stepKey = sha3_256("awake/ack" + base64PaddedIkm)
```

### 3.5.2 Payload

| Field  | Value                                                     | Description                                            | Required |
| ------ | --------------------------------------------------------- | ------------------------------------------------------ | -------- |
| `awv`  | `"0.1.0"`                                                 | AWAKE message version                                  | Yes      |
| `type` | `"awake/ack"`                                             | "AWAKE Acknowledgment" message type                    | Yes      |
| `ack`  | `sha3_256(stepKey)`                                       |                                                        | Yes      |

### 3.5.3 Extended Fields

This payload MAY contain additional fields. This is often useful if dovetailing the ACK with the first message of a session using the 

The OKM (`stepKey` above) MAY be used to encrypt these additional fields.

# 4 FAQ

## Why RSA-OAEP?
 
The temporary key is an RSA-OAEP key due to its ubquity, including support for non-extractable private keys in the [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web\_Crypto\_API). A non-extractable key is RECOMMENDED whenever supported by the host platform.


## Why not ECC?

RSA is used because it is available with a nonexportable key in browsers, is ubiquitous on all other systems, and is not considered likely backdoored (the NIST ECCs are [considered highly suspect](http://safecurves.cr.yp.to)).


Note that there is nothing special about AES256-GCM. This key is symmetric and will be available in memory. As such, this protocol gains little from the WebCrypto API aside from potential hardware acceleration (which can be helpful against certain timings attacks).

In a future version, AES-GCM may be replaced with AES-SIV-GCM or XChaCha20-Poly1305.


Eve 🦹‍♀️ has no incentive to delegate rights other than to hide from detection. However, in this scenario where she somehow already has a valid UCAN, the game was already over. There are remedies available (revocation & rotation) were that to happen. AWAKE aims to minimize this possibility from the outset (Alice 👩‍💻 would have to agree to granting Eve 🦹‍♀️ these rights due to human error).


# TODOS

* [ ] Timeouts
* [ ] Cancelation messages
* [ ] Errors
* [ ] Requestor specify purpose of request
* [ ] Add subsection about session key to intro
* [ ] Case insensitivity worth it?
