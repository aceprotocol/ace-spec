#!/usr/bin/env python3
"""Generate the canonical cross-language ACE test vectors (``ace-spec/test-vectors.json``).

Self-contained: every expectation is written here and cross-checked against the
Python SDK before anything is published. Install the Python SDK (``pip install -e
sdk-py``) and run this script. Only ``vectors.encryptedMessage`` (and the baseline
envelope derived from it) changes between runs: X-Wing encapsulation is randomized.

Runner rules shared by all SDKs are documented next to each section in
``vectors.<section>.rules`` (when a section needs them).
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import json
import os
import typing

from ace import (
    COMMERCE_EXT,
    ACEError,
    AgentProfile,
    ReplayDetector,
    SoftwareIdentity,
    ThreadStateMachine,
    create_message,
    create_registration_file,
    create_registration_request,
    decode_envelope,
    envelope_fingerprint,
    parse_message,
    verify_peer_record,
    verify_registration_file,
    verify_registration_request,
)
from ace import _xwing
from ace._encoding import canonical_state_bytes, encode_signature, from_base64, is_https_url
from ace.ext import ext_canonical
from ace._signing import (
    ED25519_L,
    SECP256K1_N,
    build_sign_data,
    encode_payload,
    verify_signature,
)
from ace.auth import RelayAuthRequest, create_auth_headers, parse_auth_headers, verify_auth_headers
from ace.discovery import adopt_decision
from ace.encryption import ACE_KEM_SALT, compute_conversation_id
from ace.messages import decode_body
from ace.registration import _KEEP as SDK_KEEP, registration_payload
from ace.state_machine import ThreadEvent, ThreadState
from ace.audit import (AuditTree, audit_checkpoint_digest, audit_commitment, create_audit_checkpoint,
                       create_audit_witness_receipt)
from ace.grants import (ResourcePolicy, create_execution_grant, execution_grant_digest, execution_intent_digest,
                        verify_execution_grant_chain)
from ace.principal import (
    PrincipalSigner,
    check_principal_rules,
    create_principal_record,
    principal_payload,
    principal_sign_data,
    validate_principal_record,
)
from ace.types import PrincipalKey, PrincipalRecord

from client_vectors import client_vectors

HERE = os.path.dirname(os.path.abspath(__file__))
_args = argparse.ArgumentParser(description="Generate ace-spec/test-vectors.json.")
_args.add_argument("--out", default=os.path.normpath(os.path.join(HERE, "..", "test-vectors.json")),
                   help="output path (default: ace-spec/test-vectors.json)")
OUT = _args.parse_args().out
ECONOMIC = ["rfq", "offer", "accept", "reject", "invoice", "receipt", "deliver", "confirm"]


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def seed(label: str) -> bytes:
    return hashlib.sha256(f"ace-test-vector-v1:{label}".encode()).digest()


def expect_error(fn, code: str) -> None:
    try:
        fn()
    except ACEError as exc:
        assert exc.code == code, f"expected {code}, got {exc.code}: {exc.message}"
        return
    raise AssertionError(f"expected {code}, got success")


def outcome(fn) -> str:
    try:
        r = fn()
    except ACEError as exc:
        return "error:" + exc.code
    return r


# =====================================================================================
# X-Wing: draft-connolly-cfrg-xwing-kem-11, Appendix C, vectors 1-3 (verbatim, hex).
# =====================================================================================

XWING_VECTORS = [
    {
        "seed": "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
        "publicKey": "e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3da5fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34244e66969cf15b3b2a785329f61b096b277ea037383479a6b556de7231fe4b7fa9c9ac24c0699a0018a5253401bacfa905ca816573e56a2d2e067e9b7287533ba13a937dedb31fa44baced40769923610034ae31e619a170245199b3c5c39864859fe1b4c9717a07c30495bdfb98a0a002ccf56c1286cef5041dede3c44cf16bf562c7448518026b3d8b9940680abd38a1575fd27b58da063bfac32c39c30869374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2aea10463111c709f69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545eae13293460b3acb37ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7bad4da40b0501e1c753efe73053c87014e8661c33099afe8bede414a5b1aa27d8392b3e131e9a70c1055878240cad0f40d5fe3cdf85236ead97e2a97448363b2808caafd516cd25052c5c362543c2517e4acd0e60ec07163009b6425fc32277acee71c24bab53ed9f29e74c66a0a3564955998d76b96a9a8b50d1635a4d7a67eb42df5644d330457293a8042f53cc7a69288f17ed55827e82b28e82665a86a14fbd96645eca8172c044f83bc0d8c0b4c8626985631ca87af829068f1358963cb333664ca482763ba3b3bb208577f9ba6ac62c25f76592743b64be519317714cb4102cb7b2f9a25b2b4f0615de31decd9ca55026d6da0b65111b16fe52feed8a487e144462a6dba93728f500b6ffc49e515569ef25fed17aff520507368253525860f58be3be61c964604a6ac814e6935596402a520a4670b3d284318866593d15a4bb01c35e3e587ee0c67d2880d6f2407fb7a70712b838deb96c5d7bf2b44bcf6038ccbe33fbcf51a54a584fe90083c91c7a6d43d4fb15f48c60c2fd66e0a8aad4ad64e5c42bb8877c0ebec2b5e387c8a988fdc23beb9e16c8757781e0a1499c61e138c21f216c29d076979871caa6942bafc090544bee99b54b16cb9a9a364d6246d9f42cce53c66b59c45c8f9ae9299a75d15180c3c952151a91b7a10772429dc4cbae6fcc622fa8018c63439f890630b9928db6bb7f9438ae4065ed34d73d486f3f52f90f0807dc88dfdd8c728e954f1ac35c06c000ce41a0582580e3bb57b672972890ac5e7988e7850657116f1b57d0809aaedec0bede1ae148148311c6f7e317346e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be1c9692ab8e1bbb12839573cce19df183b45835bbb55052f9fc66a1678ef2a36dea78411e6c8d60501b4e60592d13698a943b509185db912e2ea10be06171236b327c71716094c964a68b03377f513a05bcd99c1f346583bb052977a10a12adfc758034e5617da4c1276585e5774e1f3b9978b09d0e9c44d3bc86151c43aad185712717340223ac381d21150a04294e97bb13bbda21b5a182b6da969e19a7fd072737fa8e880a53c2428e3d049b7d2197405296ddb361912a7bcf4827ced611d0c7a7da104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c256914193ff7349042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69859edb06eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534",
        "ciphertext": "b83aa828d4d62b9a83ceffe1d3d3bb1ef31264643c070c5798927e41fb07914a273f8f96e7826cd5375a283d7da885304c5de0516a0f0654243dc5b97f8bfeb831f68251219aabdd723bc6512041acbaef8af44265524942b902e68ffd23221cda70b1b55d776a92d1143ea3a0c475f63ee6890157c7116dae3f62bf72f60acd2bb8cc31ce2ba0de364f52b8ed38c79d719715963a5dd3842d8e8b43ab704e4759b5327bf027c63c8fa857c4908d5a8a7b88ac7f2be394d93c3706ddd4e698cc6ce370101f4d0213254238b4a2e8821b6e414a1cf20f6c1244b699046f5a01caa0a1a55516300b40d2048c77cc73afba79afeea9d2c0118bdf2adb8870dc328c5516cc45b1a2058141039e2c90a110a9e16b318dfb53bd49a126d6b73f215787517b8917cc01cabd107d06859854ee8b4f9861c226d3764c87339ab16c3667d2f49384e55456dd40414b70a6af841585f4c90c68725d57704ee8ee7ce6e2f9be582dbee985e038ffc346ebfb4e22158b6c84374a9ab4a44e1f91de5aac5197f89bc5e5442f51f9a5937b102ba3beaebf6e1c58380a4a5fedce4a4e5026f88f528f59ffd2db41752b3a3d90efabe463899b7d40870c530c8841e8712b733668ed033adbfafb2d49d37a44d4064e5863eb0af0a08d47b3cc888373bc05f7a33b841bc2587c57eb69554e8a3767b7506917b6b70498727f16eac1a36ec8d8cfaf751549f2277db277e8a55a9a5106b23a0206b4721fa9b3048552c5bd5b594d6e247f38c18c591aea7f56249c72ce7b117afcc3a8621582f9cf71787e183dee09367976e98409ad9217a497df888042384d7707a6b78f5f7fb8409e3b535175373461b776002d799cbad62860be70573ecbe13b246e0da7e93a52168e0fb6a9756b895ef7f0147a0dc81bfa644b088a9228160c0f9acf1379a2941cd28c06ebc80e44e17aa2f8177010afd78a97ce0868d1629ebb294c5151812c583daeb88685220f4da9118112e07041fcc24d5564a99fdbde28869fe0722387d7a9a4d16e1cc8555917e09944aa5ebaaaec2cf62693afad42a3f518fce67d273cc6c9fb5472b380e8573ec7de06a3ba2fd5f931d725b493026cb0acbd3fe62d00e4c790d965d7a03a3c0b4222ba8c2a9a16e2ac658f572ae0e746eafc4feba023576f08942278a041fb82a70a595d5bacbf297ce2029898a71e5c3b0d1c6228b485b1ade509b35fbca7eca97b2132e7cb6bc465375146b7dceac969308ac0c2ac89e7863eb8943015b24314cafb9c7c0e85fe543d56658c213632599efabfc1ec49dd8c88547bb2cc40c9d38cbd3099b4547840560531d0188cd1e9c23a0ebee0a03d5577d66b1d2bcb4baaf21cc7fef1e03806ca96299df0dfbc56e1b2b43e4fc20c37f834c4af62127e7dae86c3c25a2f696ac8b589dec71d595bfbe94b5ed4bc07d800b330796fda89edb77be0294136139354eb8cd37591578f9c600dd9be8ec6219fdd507adf3397ed4d68707b8d13b24ce4cd8fb22851bfe9d632407f31ed6f7cb1600de56f17576740ce2a32fc5145030145cfb97e63e0e41d354274a079d3e6fb2e15",
        "sharedSecret": "d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384",
        "eseed": "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2",
    },
    {
        "seed": "badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea",
        "publicKey": "0333285fa253661508c9fb444852caa4061636cb060e69943b431400134ae1fbc02287247cb38068bbb89e6714af10a3fcda6613acc4b5e4b0d6eb960c302a0253b1f507b596f0884d351da89b01c35543214c8e542390b2bc497967961ef10286879c34316e6483b644fc27e8019d73024ba1d1cc83650bb068a5431b33d1221b3d122dc1239010a55cb13782140893f30aca7c09380255a0c621602ffbb6a9db064c1406d12723ab3bbe2950a21fe521b160b30b16724cc359754b4c88342651333ea9412d5137791cf75558ebc5c54c520dd6c622a059f6b332ccebb9f24103e59a297cd69e4a48a3bfe53a5958559e840db5c023f66c10ce23081c2c8261d744799ba078285cfa71ac51f44708d0a6212c3993340724b3ac38f63e82a889a4fc581f6b8353cc6233ac8f5394b6cca292f892360570a3031c90c4da3f02a895677390e60c24684a405f69ccf1a7b95312a47c844a4f9c2c4a37696dc10072a87bf41a2717d45b2a99ce09a4898d5a3f6b67085f9a626646bcf369982d483972b9cd7d244c4f49970f766a22507925eca7df99a491d80c27723e84c7b49b633a46b46785a16a41e02c538251622117364615d9c2cdaa1687a860c18bfc9ce8690efb2a524cb97cdfd1a4ea661fa7d08817998af838679b07c9db8455e2167a67c14d6a347522e89e8971270bec858364b1c1023b82c483cf8a8b76f040fe41c24dec2d49f6376170660605b80383391c4abad1136d874a77ef73b440758b6e7059add20873192e6e372e069c22c5425188e5c240cb3a6e29197ad17e87ec41a813af68531f262a6db25bbdb8a15d2ed9c9f35b9f2063890bd26ef09426f225aa1e6008d31600a29bcdf3b10d0bc72788d35e25f4976b3ca6ac7cbf0b442ae399b225d9714d0638a864bda7018d3b7c793bd2ace6ac68f4284d10977cc029cf203c5698f15a06b162d6c8b4fd40c6af40824f9c6101bb94e9327869ab7efd835dfc805367160d6c8571e3643ac70cbad5b96a1ad99352793f5af71705f95126cb4787392e94d808491a2245064ba5a7a30c066301392a6c315336e10dbc9c2177c7af382765b6c88eeab51588d01d6a95747f3652dc5b5c401a23863c7a0343737c737c99287a40a90896d4594730b552b910d23244684206f0eb842fb9aa316ab182282a75fb72b6806cea4774b822169c386a58773c3edc8229d85905abb87ac228f0f7a2ce9a497bb5325e17a6a82777a997c036c3b862d29c14682ad325a9600872f3913029a1588648ba590a7157809ff740b5138380015c40e9fb90f0311107946f28e5962e21666ad65092a3a60480cd16e61ff7fb5b44b70cf12201878428ef8067fceb1e1dcb49d66c773d312c7e53238cb620e126187009472d41036b702032411dc96cb750631df9d99452e495deb4300df660c8d35f32b424e98c7ed14b12d8ab11a289ac63c50a24d52925950e49ba6bf4c2c38953c92d60b6cd034e575c711ac41bfa66951f62b9392828d7b45aed377ac69c35f1c6b80f388f34e0bb9ce8167eb2bc630382825c396a407e905108081b444ac8a07c2507376a750d18248ee0a81c4318d9a38fc44c3b41e8681f87c34138442659512c41276e1cc8fc4eb66e12727bcb5a9e0e405cdea21538d6ea885ab169050e6b91e1b69f7ed34bcbb48fd4c562a576549f85b528c953926d96ea8a160b8843f1c89c62",
        "ciphertext": "c93beb22326705699bbc3d1d0aa6339be7a405debe61a7c337e1a91453c097a6f77c130639d1aaeb193175f1a987aa1fd789a63c9cd487ebd6965f5d8389c8d7c8cfacbba4b44d2fbe0ae84de9e96fb11215d9b76acd51887b752329c1a3e0468ccc49392c1e0f1aad61a73c10831e60a9798cb2e7ec07596b5803db3e243ecbb94166feade0c9197378700f8eb65a43502bbac4605992e2de2b906ab30ba401d7e1ff3c98f42cfc4b30b974d3316f331461ac05f43e0db7b41d3da702a4f567b6ee7295199c7be92f6b4a47e7307d34278e03c872fb48647c446a64a3937dccd7c6d8de4d34b9dea45a0b065ef15b9e94d1b6df6dca7174d9bc9d14c6225e3a78a58785c3fe4e2fe6a0706f3365389e4258fbb61ecf1a1957715982b3f1844424e03acd83da7eee50573f6cd3ff396841e9a00ad679da92274129da277833d0524674feea09a98d25b888616f338412d8e65e151e65736c8c6fb448c9260fa20e7b2712148bcd3a0853865f50c1fc9e4f201aee3757120e034fd509d954b7a749ff776561382c4cb64cebcbb6aa82d04cd5c2b40395ecaf231bde8334ecfd955d09efa8c6e7935b1cb0298fb8b6740be4593360eed5f129d59d98822a6cea37c57674e919e84d6b90f695fca58e7d29092bd70f7c97c6dfb021b9f87216a6271d8b144a364d03b6bf084f972dc59800b14a2c008bbd0992b5b82801020978f2bdddb3ca3367d876cffb3548dab695a29882cae2eb5ba7c847c3c71bd0150fa9c33aac8e6240e0c269b8e295ddb7b77e9c17bd310be65e28c0802136d086777be5652d6f1ac879d3263e9c712d1af736eac048fe848a577d6afaea1428dc71db8c430edd7b584ae6e6aeaf7257aff0fd8fe25c30840e30ccfa1d95118ef0f6657367e9070f3d97a2e9a7bae19957bd707b00e31b6b0ebb9d7df4bd22e44c060830a194b5b8288353255b52954ff5905ab2b126d9aa049e44599368c27d6cb033eae5182c2e1504ee4e3745f51488997b8f958f0209064f6f44a7e4de5226d5594d1ad9b42ac59a2d100a2f190df873a2e141552f33c923b4c927e8747c6f830c441a8bd3c5b371f6b3ab8103ebcfb18543aefc1beb6f776bbfd5344779f4aa23daaf395f69ec31dc046b491f0e5cc9c651dfc306bd8f2105be7bc7a4f4e21957f87278c771528a8740a92e2daefa76a3525f1fae17ec4362a2700988001d860011d6ca3a95f79a0205bcf634cef373a8ea273ff0f4250eb8617d0fb92102a6aa09cf0c3ee2cad1ad96438c8e4dfd6ee0fcc85833c3103dd6c1600cd305bc2df4cda89b55ca237a3f9c3f82390074ff30825fc750130ebaf13d0cf7556d2c52a98a4bad39ca5d44aaadeaef775c695e64d06e966acfcd552a14e2df6c63ae541f0fa88fc48263089685704506a21a03856ce65d4f06d54f3157eeabd62491cb4ac7bf029e79f9fbd4c77e2a3588790c710e611da8b2040c76a61507a8020758dcc30894ad018fef98e401cc54106e20d94bd544a8f0e1fd0500342d123f618aa8c91bdf6e0e03200693c9651e469aee6f91c98bea4127ae66312f4ae3ea155b67",
        "sharedSecret": "f2e86241c64d60f6649fbc6c5b7d17180b780a3f34355e64a85749949c45f150",
        "eseed": "17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdefaee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32d",
    },
    {
        "seed": "ef58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c9",
        "publicKey": "36244278824f77c621c660892c1c3886a9560caa52a97c461fd3958a598e749bbc8c7798ac8870bac7318ac2b863000ca3b0bdcbbc1ccfcb1a30875df9a76976763247083e646ccb2499a4e4f0c9f4125378ba3da1999538b86f99f2328332c177d1192b849413e65510128973f679d23253850bb6c347ba7ca81b5e6ac4c574565c731740b3cd8c9756caac39fba7ac422acc60c6c1a645b94e3b6d21485ebad9c4fe5bb4ea0853670c5246652bff65ce8381cb473c40c1a0cd06b54dcec11872b351397c0eaf995bebdb6573000cbe2496600ba76c8cb023ec260f0571e3ec12a9c82d9db3c57b3a99e8701f78db4fabc1cc58b1bae02745073a81fc8045439ba3b885581a283a1ba64e103610aabb4ddfe9959e7241011b2638b56ba6a982ef610c514a57212555db9a98fb6bcf0e91660ec15dfa66a67408596e9ccb97489a09a073ffd1a0a7ebbe71aa5ff793cb91964160703b4b6c9c5390842c2c905d4a9f88111fed57874ba9b03cf611e70486edf539767c7485189d5f1b08e32a274dc24a39c918fd2a4dfa946a8c897486f2c974031b2804aabc81749db430b85311372a3b8478868200b40e043f7bf4a1c3a08b0771b431e342ee277410bca034a0c77086c8f702b3aed2b4108bbd3af471633373a1ac74b128b148d1b9412aa66948cac6dc6614681fda02ca86675d2a756003c49c50f06e13c63ce4bc9f321c860b202ee931834930011f485c9af86b9f642f0c353ad305c66996b9a136b753973929495f0d8048db75529edcb4935904797ac66605490f66329c3bb36b8573a3e00f817b3082162ff106674d11b261baae0506cde7e69fdce93c6c7b59b9d4c759758acf287c2e4c4bfab5170a9236daf21bdb6005e92464ee8863f845cf37978ef19969264a516fe992c93b5f7ae7cb6718ac69257d630379e4aac6029cb906f98d91c92d118c36a6d16115d4c8f16066078badd161a65ba51e0252bc358c67cd2c4beab2537e42956e08a39cfccf0cd875b5499ee952c83a162c68084f6d35cf92f71ec66baec74ab87e2243160b64df54afb5a07f78ec0f5c5759e5a4322bca2643425748a1a97c62108510c44fd9089c5a7c14e57b1b77532800013027cff91922d7c935b4202bb507aa47598a6a5a030117210d4c49c174700550ad6f82ad40e965598b86bc575448eb19d70380d465c1f870824c026d74a2522a799b7b122d06c83aa64c0974635897261433914fdfb14106c230425a83dc8467ad8234f086c72a47418be9cfb582b1dcfa3d9aa45299b79fff265356d8286a1ca2f3c2184b2a70d15289e5b202d03b64c735a867b1154c55533ff61d6c296277011848143bc85a4b823040ae025a29293ab77747d85310078682e0ba0ac236548d905a79494324574d417c7a3457bd5fb5253c4876679034ae844d0d05010fec722db5621e3a67a2d58e2ff33b432269169b51f9dcc095b8406dc1864cf0aeb6a2132661a38d641877594b3c51892b9364d25c63d637140a2018d10931b0daa5a2f2a405017688c991e586b522f94b1132bc7e87a63246475816c8be9c62b731691ab912eb656ce2619225663364701a014b7d0337212caa2ecc731f34438289e0ca4590a276802d980056b5d0d316cae2ecfea6d86696a9f161aa90ad47eaad8cadd31ae3cbc1c013747dfee80fb35b5299f555dcc2b787ea4f6f16ffdf66952461",
        "ciphertext": "0d2e38cbf17a2e2e4e0c87a94ca1e7701ae1552e02509b3b00f9c82c39e3fd435b05b91275f47abc9f1021429a26a346598cd6cd9efdc8adc1dbc35036d0290bf89733c835309202232f9bf652ea82f3d49280d6e8a3bd3135fb883445ab5b074d949c5350c7c7d6ac59905bdbfce6639da8a9d4b390ecc1dd05522d2956f2d37a05593996e5cb3fd8d5a9eb52417732e1ebf545588713b4760227115aab7ada178dadbca583b26cfedba2888a0c95b950bf07f750d7aa8103798aa3470a042c0105c6a037de2f9ebc396021b2ba2c16aba696fbac3454dc8e053b8fa55edd45215eeb57a1eab9106fb426b375a9b9e5c3419efc7610977e72640f9fd1b2ec337de33c35e5a7581b2aae4d8ee86d2e0ebf82a1350714de50d2d788687878a19644ae4e3175e8d59dc90171b3badeff65aeaf600e5e5483a3595fdeb40cbafcbd040c29a2f6900533ae999d24f54dfcef748c30313ca447cdddfa57ad78eaa890e90f3f7bf8d116968a5713cc75fd0408f36364fa265c5617039304eaeac4cbee6fc49b9fe2276768cdbec2d73a507b543cc028dc1b154b7c2b0412254c466a94a8d6ea3a47e1743469bd45c08f54cf965884be3696e961741ede16e3b1bc4feb93faaef31d911dc0cb3fa90bcda991959a9d2cbc817a5564c5c01177a59e9577589ea344d60cf5b0aa39f31863febd54603ca87ad2363c766642a3f52557bcd9e4c05a87665842ba336b83156a677030f0bad531a8387a1486a599caa748fcea7bdc1eb63f3cdb97173551ab7c1c36b69acbbdb2ff7a1e7bc70439632ddc67b97f3da1f59b3c1588515957cb8a2f86ab635ce0a78b7cdf24eac3445e8fc8b79ba04da9e903f49a7d912c197a84b4cfabc779b97d24788419bcf58035db99717edb9fd1c1df8c4005f700eabba528ddfcbaeda6dd30754f795948a34c9319ab653524b19931c7900c4167988af52292fe902e746b524d20ceffb4339e8f5535f41cf35f0f8ea8b4a7b949c5d2381116b146e9b913a83a3fa1c65ff9468c835fe4114554a6c66a80e1c9a6bb064b380be3c95e5595ec979bf1c85aa938938e3f10e72b0c87811969e8ab0d83de0b0604c4016ac3a015e19514089271bdc6ebf2ec56fab6018e44de749b4c36cc235e370da8466dbdc253542a2d704eb3316fd70d5d238cb7eaaf05966d973f62c7ef43b9a806f4ed213ac8099ea15d61a902444160883f6bf441a3e1469945c9b79489ea18390f1ebc83caca10bdb8f2429877b52bd44c94a228ef91c392ef5398c5c83982701318ccedab92f7a279c4fddebaa7fe5e986c48b7d8135b3fe4cd15be2004ce73ff86b1e55f8ecd6ba5b8114315f8e716ef3ab0a64564a4644651166ebd68b1f783e2e443dbccadfe189368647629f1a12215840b7f1d026de2f665c2eb023ff51a6df160912811ee03444ae4227fb941dc9ec4f31b445006fd384de5e60e0a5061b50cb1202f863090fc05eb814e2d42a03586c0b56f533847ac7b8184ce9690bc8dece32a88ca934f541d4cc520fa64de6b6e1c3c8e03db5971a445992227c825590688d203523f527161137334",
        "sharedSecret": "953f7f4e8c5b5049bdc771d1dffada0dd961477d1a2ae0988baa7ea6898d893f",
        "eseed": "22a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b",
    },
]

for v in XWING_VECTORS:
    s = bytes.fromhex(v["seed"])
    assert _xwing.public_key_from_seed(s).hex() == v["publicKey"]
    assert _xwing.decapsulate(bytes.fromhex(v["ciphertext"]), s).hex() == v["sharedSecret"]

# =====================================================================================
# Agents
# =====================================================================================

alice = SoftwareIdentity("ed25519", seed("alice-signing"), seed("alice-encryption"))
bob = SoftwareIdentity("secp256k1", seed("bob-signing"), seed("bob-encryption"))
carol = SoftwareIdentity("secp256k1", seed("carol-signing"), seed("carol-encryption"))
A, B = alice.get_ace_id(), bob.get_ace_id()
THIRD = "ace:sha256:" + "1" * 64

TIMESTAMP = 1741000000
conversation_id = compute_conversation_id(alice.get_encryption_public_key(), bob.get_encryption_public_key())


def agent_json(ident: SoftwareIdentity) -> dict:
    exp = ident.export_private_key()
    return {
        "scheme": exp["scheme"],
        "signingPrivateKey": exp["signingPrivateKey"],
        "encryptionPrivateKey": exp["encryptionPrivateKey"],
        "signingPublicKey": b64(ident.get_signing_public_key()),
        "encryptionPublicKey": b64(ident.get_encryption_public_key()),
        "address": ident.get_address(),
        "aceId": ident.get_ace_id(),
    }


# =====================================================================================
# signData / signature
# =====================================================================================

MESSAGE_ID = "550e8400-e29b-41d4-a716-446655440000"
THREAD_ID = "interop-test"
KEM_CIPHERTEXT = b"\xaa" * 1120
CIPHERTEXT = b"fake-ciphertext-for-testing-only"
message_payload = encode_payload(B, conversation_id, MESSAGE_ID, KEM_CIPHERTEXT, CIPHERTEXT)
sign_data = build_sign_data("packet", A, TIMESTAMP, message_payload)
alice_sig = alice.sign(sign_data)

# =====================================================================================
# encryptedMessage (random encapsulation) + self-check
# =====================================================================================

bob_peer = verify_registration_file(create_registration_file(bob, name="Bob", endpoint="https://bob.example/ace"))
alice_peer = verify_registration_file(create_registration_file(alice, name="Alice", endpoint="https://alice.example/ace"))
EXPECTED_BODY = {"message": "hello from python"}
msg = create_message(alice, bob_peer, "text", EXPECTED_BODY, ThreadStateMachine(A), timestamp=TIMESTAMP)
envelope = msg.to_dict()
parsed = parse_message(
    decode_envelope(json.loads(json.dumps(envelope))), bob, alice_peer,
    threads=ThreadStateMachine(B), replay=ReplayDetector(horizon=TIMESTAMP - 1), clock=lambda: TIMESTAMP,
)
assert parsed.body == EXPECTED_BODY

# =====================================================================================
# envelopes
# =====================================================================================

envelope_vectors: list[dict] = []
TS_SENTINEL = 777777777777


def add_envelope(name: str, obj, valid: bool, error: str | None = None, *, ts_text: str | None = None, text: str | None = None):
    if text is None:
        if ts_text is not None:
            obj = json.loads(json.dumps(obj))
            obj["timestamp"] = TS_SENTINEL
        text = json.dumps(obj, ensure_ascii=False)
        if ts_text is not None:
            text = text.replace(str(TS_SENTINEL), ts_text)
    entry: dict = {"name": name, "json": text, "valid": valid}
    try:
        decoded = decode_envelope(json.loads(text))
        got = None
    except ACEError as exc:
        got = exc.code
    if valid:
        assert got is None, f"{name}: expected valid, got {got}"
        entry["fingerprint"] = envelope_fingerprint(decoded)
    else:
        assert got == error, f"{name}: expected {error}, got {got}"
        entry["error"] = error
    envelope_vectors.append(entry)


def flip_b64(sig: str) -> str:
    raw = bytearray(base64.b64decode(sig))
    raw[0] ^= 1
    return b64(bytes(raw))


def mutate(base=None, /, **changes):
    obj = json.loads(json.dumps(envelope if base is None else base))
    for path, value in changes.items():
        keys = path.split("__")
        target = obj
        for k in keys[:-1]:
            target = target[k]
        if value is DELETE:
            del target[keys[-1]]
        else:
            target[keys[-1]] = value
    return obj


DELETE = object()
kem_b64 = envelope["encryption"]["kemCiphertext"]
payload_b64 = envelope["encryption"]["payload"]
rfq_env = mutate(type="rfq", threadId="t1")

add_envelope("baseline", envelope, True)
add_envelope("unknown top-level and nested fields", mutate(extra={"x": 1}, encryption__extra="y", signature__extra=[1]), True)
assert envelope_vectors[1]["fingerprint"] == envelope_vectors[0]["fingerprint"]
add_envelope("threadId null", mutate(threadId=None), False, "invalid_envelope")
add_envelope("economic type without threadId", mutate(type="rfq"), False, "invalid_envelope")
add_envelope("economic type with threadId", rfq_env, False, "invalid_envelope")
add_envelope("threadId 256 code points", mutate(threadId="é" * 256), False, "invalid_envelope")
add_envelope("threadId 257 code points", mutate(threadId="é" * 257), False, "invalid_envelope")
add_envelope("threadId containing U+007F", mutate(threadId="a\u007fb"), False, "invalid_envelope")
add_envelope("threadId empty", mutate(threadId=""), False, "invalid_envelope")
add_envelope("timestamp -1", mutate(timestamp=-1), False, "invalid_envelope")
add_envelope("timestamp 2^53", mutate(timestamp=2**53), False, "invalid_envelope")
add_envelope("timestamp 2^53-1", mutate(timestamp=2**53 - 1), True)
add_envelope("timestamp 1000.0", envelope, True, ts_text="1000.0")
add_envelope("timestamp 1e3", envelope, True, ts_text="1e3")
assert envelope_vectors[-1]["fingerprint"] == envelope_vectors[-2]["fingerprint"]
add_envelope("timestamp 1000.5", envelope, False, "invalid_envelope", ts_text="1000.5")
add_envelope("timestamp string", mutate(timestamp="1000"), False, "invalid_envelope")
add_envelope("timestamp true", mutate(timestamp=True), False, "invalid_envelope")
add_envelope("messageId uppercase", mutate(messageId=envelope["messageId"].upper()), False, "invalid_envelope")
add_envelope("messageId UUIDv1", mutate(messageId="550e8400-e29b-11d4-a716-446655440000"), False, "invalid_envelope")
add_envelope("conversationId uppercase", mutate(conversationId=conversation_id.upper()), False, "invalid_envelope")
add_envelope("conversationId 63 hex", mutate(conversationId=conversation_id[:63]), False, "invalid_envelope")
add_envelope("from not an ACE ID", mutate(**{"from": "ace:sha256:" + "A" * 64}), False, "invalid_envelope")
add_envelope("unknown type", mutate(type="bid"), False, "invalid_envelope")
add_envelope("ace 1.1", mutate(ace="1.1"), False, "unsupported_version")
add_envelope("ace number", mutate(ace=1.0), False, "invalid_envelope")
add_envelope("ace missing", mutate(ace=DELETE), False, "invalid_envelope")
add_envelope("kemCiphertext 1119 bytes", mutate(encryption__kemCiphertext=b64(b"\x01" * 1119)), False, "invalid_envelope")
_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_nc = kem_b64[:-3] + _ALPHA[_ALPHA.index(kem_b64[-3]) | 1] + "=="  # 1120 % 3 == 1: low 4 bits are padding
assert _nc != kem_b64 and base64.b64decode(_nc) == base64.b64decode(kem_b64)
add_envelope("kemCiphertext non-canonical Base64", mutate(encryption__kemCiphertext=_nc), False, "invalid_envelope")
add_envelope("kemCiphertext with whitespace", mutate(encryption__kemCiphertext=kem_b64[:76] + "\n" + kem_b64[76:]), False, "invalid_envelope")
add_envelope("kemCiphertext URL-safe alphabet", mutate(encryption__kemCiphertext=b64(b"\xfb\xff" * 560).replace("+", "-").replace("/", "_")), False, "invalid_envelope")
add_envelope("payload 27 bytes", mutate(encryption__payload=b64(b"\x00" * 27)), False, "invalid_envelope")
add_envelope("payload 28 bytes", mutate(encryption__payload=b64(b"\x00" * 28)), True)
add_envelope("payload 65536 bytes", mutate(encryption__payload=b64(b"\x00" * 65536)), True)
add_envelope("payload 65537 bytes", mutate(encryption__payload=b64(b"\x00" * 65537)), False, "invalid_envelope")
add_envelope("encryption missing", mutate(encryption=DELETE), False, "invalid_envelope")
add_envelope("ed25519 signature 63 bytes", mutate(signature__value=b64(b"\x01" * 63)), False, "invalid_envelope")
add_envelope("signature scheme unknown", mutate(signature__scheme="ml-dsa-65"), False, "invalid_envelope")
_secp_hex = "0x" + "11" * 64 + "01"
add_envelope("secp256k1 value well-formed", mutate(signature__scheme="secp256k1", signature__value=_secp_hex), True)
add_envelope("secp256k1 value without 0x", mutate(signature__scheme="secp256k1", signature__value=_secp_hex[2:]), False, "invalid_envelope")
add_envelope("secp256k1 value with 0X", mutate(signature__scheme="secp256k1", signature__value="0X" + _secp_hex[2:]), False, "invalid_envelope")
add_envelope("secp256k1 value uppercase hex", mutate(signature__scheme="secp256k1", signature__value="0x" + "AA" * 65), False, "invalid_envelope")
add_envelope("secp256k1 value 129 hex digits", mutate(signature__scheme="secp256k1", signature__value=_secp_hex[:-1]), False, "invalid_envelope")
add_envelope("top-level array", None, False, "invalid_envelope", text="[]")
# 04 § Envelope: the cleartext envelope rejects each private-content key, even if null.
add_envelope("type null", mutate(type=None), False, "invalid_envelope")
add_envelope("schemaDigest in the envelope", mutate(schemaDigest="ab" * 32), False, "invalid_envelope")
add_envelope("schemaDigest null", mutate(schemaDigest=None), False, "invalid_envelope")
add_envelope("body in the envelope", mutate(body={"message": "hi"}), False, "invalid_envelope")
add_envelope("body null", mutate(body=None), False, "invalid_envelope")

# =====================================================================================
# bodies (internal decode + validate_body; the error is always invalid_body)
# =====================================================================================

body_vectors: list[dict] = []


def add_body(name: str, type_: str, text: str | None, valid: bool, *, raw: bytes | None = None):
    data = raw if raw is not None else text.encode("utf-8")
    try:
        decode_body(type_, data)
        got = True
    except ACEError as exc:
        assert exc.code == "invalid_body", (name, exc.code)
        got = False
    assert got == valid, f"body {name}: expected valid={valid}"
    entry = {"name": name, "type": type_}
    if raw is not None:
        entry["bodyHex"] = raw.hex()
    else:
        entry["bodyJson"] = text
    entry["valid"] = valid
    body_vectors.append(entry)


MINIMAL = {
    "rfq": {"need": "translate"},
    "offer": {"price": "10", "currency": "USDC"},
    "accept": {"offerId": "00000000-0000-4000-8000-000000000001"},
    "reject": {},
    "invoice": {"offerId": "00000000-0000-4000-8000-000000000001", "amount": "10", "currency": "USDC", "settlementMethod": "eip155:8453/erc20"},
    "receipt": {"referenceId": "00000000-0000-4000-8000-000000000001", "amount": "10", "currency": "USDC", "settlementMethod": "eip155:8453/erc20", "proof": {"txHash": "0x01"}},
    "deliver": {"type": "inline", "content": "bonjour"},
    "confirm": {"deliverId": "00000000-0000-4000-8000-000000000001"},
    "info": {"message": "hi"},
    "text": {"message": "hi"},
    "request": {"action": "pay", "summary": "Pay 1 USDC"},
    "decision": {"requestId": "00000000-0000-4000-8000-000000000001", "outcome": "approve"},
    "report": {"action": "pay", "summary": "paid", "outcome": "ok"},
}
REQUIRED = {
    "rfq": ["need"], "offer": ["price", "currency"], "accept": ["offerId"], "reject": [],
    "invoice": ["offerId", "amount", "currency", "settlementMethod"],
    "receipt": ["referenceId", "amount", "currency", "settlementMethod", "proof"],
    "deliver": ["type", "content"], "confirm": ["deliverId"], "info": ["message"], "text": ["message"],
    "request": ["action", "summary"], "decision": ["requestId", "outcome"], "report": ["action", "summary", "outcome"],
}


def j(o) -> str:
    return json.dumps(o, ensure_ascii=False, separators=(",", ":"))


for t, body in MINIMAL.items():
    add_body(f"{t} minimal", t, j(body), True)
    for f in REQUIRED[t]:
        add_body(f"{t} missing {f}", t, j({k: v for k, v in body.items() if k != f}), False)
        add_body(f"{t} {f} null", t, j({**body, f: None}), False)
        add_body(f"{t} {f} wrong type", t, j({**body, f: 123 if f != "proof" else "x"}), False)
add_body("deliver reference minimal", "deliver", j({"type": "reference", "uri": "https://example.com/r"}), True)
add_body("deliver reference without uri", "deliver", j({"type": "reference", "content": "x"}), False)
add_body("deliver inline without content", "deliver", j({"type": "inline", "uri": "https://example.com/r"}), False)
add_body("deliver type x", "deliver", j({"type": "x", "content": "a", "uri": "https://example.com"}), False)
add_body("deliver metadata array", "deliver", j({**MINIMAL["deliver"], "metadata": []}), False)
add_body("deliver contentType null", "deliver", j({**MINIMAL["deliver"], "contentType": None}), True)
add_body("receipt proof array", "receipt", j({**MINIMAL["receipt"], "proof": []}), False)
add_body("rfq optional nulls", "rfq", j({"need": "x", "maxPrice": None, "currency": None, "ttl": None}), True)
add_body("rfq all optionals", "rfq", j({"need": "x", "maxPrice": "5", "currency": "USDC", "ttl": 60}), True)
add_body("rfq maxPrice number", "rfq", j({"need": "x", "maxPrice": 5}), False)
add_body("offer terms null", "offer", j({**MINIMAL["offer"], "terms": None}), True)
add_body("invoice settlementDetails null", "invoice", j({**MINIMAL["invoice"], "settlementDetails": None}), True)
add_body("invoice settlementDetails string", "invoice", j({**MINIMAL["invoice"], "settlementDetails": "x"}), False)
add_body("reject reason number", "reject", j({"reason": 1}), False)
add_body("ttl 1.5", "rfq", '{"need":"x","ttl":1.5}', False)
add_body("ttl -1", "rfq", '{"need":"x","ttl":-1}', False)
add_body("ttl true", "rfq", '{"need":"x","ttl":true}', False)
add_body("ttl string", "offer", '{"price":"1","currency":"USDC","ttl":"60"}', False)
add_body("ttl 2^53", "offer", '{"price":"1","currency":"USDC","ttl":9007199254740992}', False)
add_body("ttl 1e3", "rfq", '{"need":"x","ttl":1e3}', True)
add_body("ttl 60.0", "offer", '{"price":"1","currency":"USDC","ttl":60.0}', True)
add_body("NaN", "text", '{"message":"x","n":NaN}', False)
add_body("Infinity", "text", '{"message":"x","n":Infinity}', False)
add_body("-Infinity", "text", '{"message":"x","n":-Infinity}', False)
add_body("1e400", "text", '{"message":"x","n":1e400}', False)
add_body("integer literal of 400 digits", "text", '{"message":"x","n":1' + "0" * 399 + "}", False)
add_body("depth 32", "text", '{"message":"x","d":' + "[" * 32 + "]" * 32 + "}", True)
add_body("depth 33", "text", '{"message":"x","d":' + "[" * 33 + "]" * 33 + "}", False)
add_body("top-level array", "text", '[{"message":"x"}]', False)
add_body("top-level string", "text", '"x"', False)
add_body("top-level null", "text", "null", False)
add_body("invalid UTF-8", "text", None, False, raw=b'{"message":"\xff"}')
add_body("not JSON", "text", '{"message":"x"', False)
add_body("extra fields", "text", j({"message": "x", "extra": {"nested": [1, 2.5, None, True]}}), True)
add_body("empty required string", "text", j({"message": ""}), True)
add_body("non-ASCII", "text", j({"message": "中文 / émoji 🚀"}), True)
# principal message bodies (09 § Principal Messages)
_REF = {"conversationId": "ab" * 32, "messageId": MESSAGE_ID}
add_body("request all optionals", "request", j({**MINIMAL["request"], "ref": {**_REF, "threadId": "deal-1"}, "amount": "1",
                                               "currency": "USDC", "details": {"scheme": "exact", "payTo": "x"}, "ttl": 60}), True)
add_body("request optional nulls", "request", j({**MINIMAL["request"], "ref": None, "amount": None, "currency": None,
                                                "details": None, "ttl": None}), True)
add_body("request ref without threadId", "request", j({**MINIMAL["request"], "ref": _REF}), True)
add_body("request ref unknown member ignored", "request", j({**MINIMAL["request"], "ref": {**_REF, "extra": {"x": 1}}}), True)
add_body("request ref threadId null", "request", j({**MINIMAL["request"], "ref": {**_REF, "threadId": None}}), True)
add_body("request ref threadId empty", "request", j({**MINIMAL["request"], "ref": {**_REF, "threadId": ""}}), False)
add_body("request ref threadId 257 code points", "request", j({**MINIMAL["request"], "ref": {**_REF, "threadId": "é" * 257}}), False)
add_body("request ref conversationId uppercase", "request", j({**MINIMAL["request"], "ref": {**_REF, "conversationId": "AB" * 32}}), False)
add_body("request ref messageId uppercase", "request", j({**MINIMAL["request"], "ref": {**_REF, "messageId": _REF["messageId"].upper()}}), False)
add_body("request ref messageId UUIDv1", "request",
         j({**MINIMAL["request"], "ref": {**_REF, "messageId": "550e8400-e29b-11d4-a716-446655440000"}}), False)
add_body("request ref missing messageId", "request", j({**MINIMAL["request"], "ref": {"conversationId": "ab" * 32}}), False)
add_body("request ref missing conversationId", "request", j({**MINIMAL["request"], "ref": {"messageId": _REF["messageId"]}}), False)
add_body("request ref array", "request", j({**MINIMAL["request"], "ref": []}), False)
add_body("request details string", "request", j({**MINIMAL["request"], "details": "x"}), False)
add_body("request details array", "request", j({**MINIMAL["request"], "details": []}), False)
add_body("request amount number", "request", j({**MINIMAL["request"], "amount": 1}), False)
add_body("request ttl 1.5", "request", '{"action":"a","summary":"s","ttl":1.5}', False)
add_body("request ttl -1", "request", '{"action":"a","summary":"s","ttl":-1}', False)
add_body("decision outcome deny with reason and result", "decision",
         j({**MINIMAL["decision"], "outcome": "deny", "reason": "no", "result": {"tx": "0x1"}}), True)
add_body("decision optional nulls", "decision", j({**MINIMAL["decision"], "reason": None, "result": None}), True)
add_body("decision outcome maybe", "decision", j({**MINIMAL["decision"], "outcome": "maybe"}), False)
add_body("decision outcome APPROVE", "decision", j({**MINIMAL["decision"], "outcome": "APPROVE"}), False)
add_body("decision outcome ok (report value)", "decision", j({**MINIMAL["decision"], "outcome": "ok"}), False)
add_body("decision result array", "decision", j({**MINIMAL["decision"], "result": []}), False)
add_body("decision result string", "decision", j({**MINIMAL["decision"], "result": "0x1"}), False)
add_body("decision reason number", "decision", j({**MINIMAL["decision"], "reason": 1}), False)
add_body("report outcome skipped with ref", "report", j({**MINIMAL["report"], "outcome": "skipped", "ref": _REF,
                                                         "requestId": _REF["messageId"], "proof": {}}), True)
add_body("report outcome failed", "report", j({**MINIMAL["report"], "outcome": "failed"}), True)
add_body("report optional nulls", "report", j({**MINIMAL["report"], "ref": None, "requestId": None, "proof": None}), True)
add_body("report outcome done", "report", j({**MINIMAL["report"], "outcome": "done"}), False)
add_body("report outcome approve (decision value)", "report", j({**MINIMAL["report"], "outcome": "approve"}), False)
add_body("report proof string", "report", j({**MINIMAL["report"], "proof": "x"}), False)
add_body("report proof array", "report", j({**MINIMAL["report"], "proof": []}), False)
add_body("report ref threadId empty", "report", j({**MINIMAL["report"], "ref": {**_REF, "threadId": ""}}), False)
add_body("report requestId number", "report", j({**MINIMAL["report"], "requestId": 1}), False)

# =====================================================================================
# transitions
# =====================================================================================

TBASE = 1741000000


def mid(i: int) -> str:
    return f"00000000-0000-4000-8000-{i:012d}"


BODY_TEMPLATES = {
    "rfq": {"need": "x"},
    "offer": {"price": "1", "currency": "USDC"},
    "accept": {"offerId": "$head"},
    "reject": {},
    "invoice": {"offerId": "$beforeHead", "amount": "1", "currency": "USDC", "settlementMethod": "x"},
    "receipt": {"referenceId": "$head", "amount": "1", "currency": "USDC", "settlementMethod": "x", "proof": {}},
    "deliver": {"type": "inline", "content": "x"},
    "confirm": {"deliverId": "$head"},
}
# Vector ordering is the declaration order of the SDK's ThreadState literal.
THREAD_STATES = typing.get_args(ThreadState)
PATHS = {
    "idle": [],
    "rfq": ["rfq:buyer"],
    "offered": ["rfq:buyer", "offer:seller"],
    "accepted": ["rfq:buyer", "offer:seller", "accept:buyer"],
    "invoiced": ["rfq:buyer", "offer:seller", "accept:buyer", "invoice:seller"],
    "paid": ["rfq:buyer", "offer:seller", "accept:buyer", "invoice:seller", "receipt:buyer"],
    "delivered": ["rfq:buyer", "offer:seller", "accept:buyer", "invoice:seller", "receipt:buyer", "deliver:seller"],
    "rejected": ["rfq:buyer", "offer:seller", "reject:buyer"],
    "confirmed": ["rfq:buyer", "offer:seller", "accept:buyer", "invoice:seller", "receipt:buyer", "deliver:seller", "confirm:buyer"],
}
ROLE_ID = {"buyer": A, "seller": B, "third": THIRD}


def synth(type_: str, ids: list[str]) -> dict:
    out = {}
    for k, v in BODY_TEMPLATES[type_].items():
        if v == "$head":
            v = ids[-1] if ids else ""
        elif v == "$beforeHead":
            v = ids[-2] if len(ids) >= 2 else ""
        out[k] = v
    return out


def run_step(sm: ThreadStateMachine, i: int, type_: str, frm: str, to: str, body: dict) -> str:
    e = ThreadEvent(conversation_id, "t1", type_, mid(i), TBASE + i, ROLE_ID[frm], ROLE_ID[to])
    return outcome(lambda: sm.apply(e, body))


def other(role: str) -> str:
    return "seller" if role == "buyer" else "buyer"


matrix: dict = {}
for state in THREAD_STATES:
    matrix[state] = {}
    for t in ECONOMIC:
        cell = {}
        for sender in ("buyer", "seller"):
            results = []
            for local in ("buyer", "seller"):
                sm = ThreadStateMachine(ROLE_ID[local])
                ids: list[str] = []
                for i, step in enumerate(PATHS[state], start=1):
                    st, frm = step.split(":")
                    r = run_step(sm, i, st, frm, other(frm), synth(st, ids))
                    assert not r.startswith("error"), (state, step, r)
                    ids.append(mid(i))
                assert sm.get_state(conversation_id, "t1") == state
                i = len(PATHS[state]) + 1
                results.append(run_step(sm, i, t, sender, other(sender), synth(t, ids)))
            assert results[0] == results[1], (state, t, sender, results)
            cell[sender] = results[0]
        matrix[state][t] = cell
# hand-checked anchors
assert matrix["idle"]["rfq"] == {"buyer": "rfq", "seller": "rfq"}
assert matrix["rfq"]["reject"] == {"buyer": "error:wrong_role", "seller": "rejected"}
assert matrix["accepted"]["receipt"] == {"buyer": "paid", "seller": "error:wrong_role"}
assert matrix["confirmed"]["rfq"]["buyer"] == "error:transition_not_allowed"
assert matrix["offered"]["offer"]["seller"] == "offered"
assert matrix["delivered"]["confirm"] == {"buyer": "confirmed", "seller": "error:wrong_role"}


def case(name: str, local: str, steps: list[tuple]) -> dict:
    """steps: (type, from, to, body, expect). Body strings '#n' are replaced with mid(n)."""
    out = []
    sm = ThreadStateMachine(ROLE_ID[local])
    for i, (t, frm, to, body, expect) in enumerate(steps, start=1):
        body = {k: (mid(int(v[1:])) if isinstance(v, str) and v.startswith("#") else v) for k, v in body.items()}
        got = run_step(sm, i, t, frm, to, body)
        assert got == expect, f"{name} step {i}: expected {expect}, got {got}"
        out.append({"type": t, "from": frm, "to": to, "body": body, "expect": expect})
    return {"name": name, "local": local, "steps": out}


RFQ, OFFER = BODY_TEMPLATES["rfq"], BODY_TEMPLATES["offer"]
INV = {"amount": "1", "currency": "USDC", "settlementMethod": "x"}
REC = {"amount": "1", "currency": "USDC", "settlementMethod": "x", "proof": {}}
DLV = BODY_TEMPLATES["deliver"]
NEG = [("rfq", "buyer", "seller", RFQ, "rfq"), ("offer", "seller", "buyer", OFFER, "offered")]
cases = [
    case("accept of a superseded offer", "buyer", NEG + [
        ("offer", "seller", "buyer", OFFER, "offered"),
        ("accept", "buyer", "seller", {"offerId": "#2"}, "error:bad_reference"),
        ("accept", "buyer", "seller", {"offerId": "#3"}, "accepted"),
    ]),
    case("invoice must reference the accepted offer", "seller", NEG + [
        ("offer", "seller", "buyer", OFFER, "offered"),
        ("accept", "buyer", "seller", {"offerId": "#3"}, "accepted"),
        ("invoice", "seller", "buyer", {"offerId": "#4", **INV}, "error:bad_reference"),
        ("invoice", "seller", "buyer", {"offerId": "#2", **INV}, "error:bad_reference"),
        ("invoice", "seller", "buyer", {"offerId": "#3", **INV}, "invoiced"),
    ]),
    case("pre-paid receipt references the accept", "buyer", NEG + [
        ("accept", "buyer", "seller", {"offerId": "#2"}, "accepted"),
        ("receipt", "buyer", "seller", {"referenceId": "#2", **REC}, "error:bad_reference"),
        ("receipt", "buyer", "seller", {"referenceId": "#3", **REC}, "paid"),
    ]),
    case("receipt references the invoice", "seller", NEG + [
        ("accept", "buyer", "seller", {"offerId": "#2"}, "accepted"),
        ("invoice", "seller", "buyer", {"offerId": "#2", **INV}, "invoiced"),
        ("receipt", "buyer", "seller", {"referenceId": "#3", **REC}, "error:bad_reference"),
        ("receipt", "buyer", "seller", {"referenceId": "#4", **REC}, "paid"),
    ]),
    case("confirm with a wrong deliverId", "buyer", NEG + [
        ("accept", "buyer", "seller", {"offerId": "#2"}, "accepted"),
        ("deliver", "seller", "buyer", DLV, "delivered"),
        ("confirm", "buyer", "seller", {"deliverId": "#3"}, "error:bad_reference"),
        ("confirm", "buyer", "seller", {"deliverId": "#4"}, "confirmed"),
    ]),
    case("missing reference field is invalid_body", "buyer", NEG + [
        ("accept", "buyer", "seller", {}, "error:invalid_body"),
    ]),
    case("third-party sender", "buyer", NEG + [
        ("offer", "third", "buyer", OFFER, "error:wrong_party"),
        ("reject", "seller", "third", {}, "error:wrong_party"),
    ]),
    case("local identity not a party", "seller", [
        ("rfq", "buyer", "third", RFQ, "error:wrong_party"),
    ]),
    case("sender equals recipient", "buyer", [
        ("rfq", "buyer", "buyer", RFQ, "error:wrong_party"),
    ]),
    case("terminal states", "buyer", NEG + [
        ("reject", "buyer", "seller", {}, "rejected"),
        ("offer", "seller", "buyer", OFFER, "error:transition_not_allowed"),
        ("rfq", "buyer", "seller", RFQ, "error:transition_not_allowed"),
    ]),
    case("rfq rejected by the seller", "seller", [
        ("rfq", "buyer", "seller", RFQ, "rfq"),
        ("reject", "seller", "buyer", {}, "rejected"),
    ]),
    case("rfq rejected by the buyer", "buyer", [
        ("rfq", "buyer", "seller", RFQ, "rfq"),
        ("reject", "buyer", "seller", {}, "error:wrong_role"),
    ]),
    case("seller may open a thread as buyer", "buyer", [
        ("rfq", "seller", "buyer", RFQ, "rfq"),
        ("offer", "seller", "buyer", OFFER, "error:wrong_role"),
        ("offer", "buyer", "seller", OFFER, "offered"),
    ]),
]
transitions = {
    "rules": (
        "Step i (1-based, counting path steps first) uses messageId '00000000-0000-4000-8000-' + i "
        "zero-padded to 12 digits and timestamp 1741000000 + i. 'to' is the other party unless given. "
        "Matrix/path bodies come from bodyTemplates: '$head' = messageId of the latest history entry, "
        "'$beforeHead' = the one before it ('' when absent). A failing step does not change state. "
        "Run the matrix with local = buyer and again with local = seller; results are identical."
    ),
    "conversationId": conversation_id,
    "threadId": "t1",
    "buyer": A,
    "seller": B,
    "third": THIRD,
    "bodyTemplates": BODY_TEMPLATES,
    "paths": PATHS,
    "matrix": matrix,
    "cases": cases,
}

# =====================================================================================
# replay
# =====================================================================================

SA, SB, SC = "ace:sha256:" + "a" * 64, "ace:sha256:" + "b" * 64, "ace:sha256:" + "c" * 64


def sender(n: int) -> str:
    return f"ace:sha256:{n:064x}"


def replay_case(name: str, capacity: int, horizon: int | None, ops: list[tuple], *, initial: dict | None = None,
                checks=None) -> dict:
    if initial is not None:
        det = ReplayDetector.from_state(initial, capacity=capacity)
    else:
        det = ReplayDetector(capacity=capacity, horizon=horizon)
    out = []
    for op in ops:
        kind, m, s, ts, *rest = op
        if kind == "commit":
            floor, expect = rest
            got = det.commit(m, s, ts, floor)
            out.append({"op": "commit", "messageId": m, "sender": s, "timestamp": ts, "floor": floor, "expect": expect})
        else:
            (expect,) = rest
            got = det.accepts(m, s, ts)
            out.append({"op": "accepts", "messageId": m, "sender": s, "timestamp": ts, "expect": expect})
        assert got == expect, f"replay {name}: {op} -> {got}"
    state = det.export_state()
    if checks:
        checks(state)
    final = canonical_state_bytes(state).decode("ascii")
    # Round trip: loading the canonical export reproduces it byte for byte.
    assert canonical_state_bytes(ReplayDetector.from_state(json.loads(final), capacity=capacity).export_state()).decode() == final
    entry: dict = {"name": name, "capacity": capacity, "horizon": horizon}
    if initial is not None:
        entry["initialStateJson"] = json.dumps(initial, separators=(",", ":"))
    entry["ops"] = out
    entry["finalStateJson"] = final
    return entry


replay_vectors = [
    replay_case("floor eviction raises H", 100, 1000, [
        ("commit", mid(1), SA, 1010, 1000, True),
        ("commit", mid(2), SA, 1020, 1000, True),
        ("commit", mid(3), SB, 1030, 1015, True),
        ("accepts", mid(1), SA, 1010, False),
        ("accepts", mid(4), SA, 1011, True),
        ("commit", mid(1), SA, 1010, 1015, False),
        ("commit", mid(2), SA, 1020, 1015, False),
    ], checks=lambda s: s["horizon"] == 1010 or (_ for _ in ()).throw(AssertionError(s))),
    replay_case("same-second entries at the floor", 100, 1000, [
        ("commit", mid(1), SA, 1010, 1000, True),
        ("commit", mid(2), SB, 1010, 1000, True),
        ("commit", mid(3), SC, 1010, 1000, True),
        ("commit", mid(4), SA, 1020, 1010, True),
        ("accepts", mid(9), SC, 1010, True),
        ("commit", mid(5), SA, 1021, 1011, True),
        ("accepts", mid(9), SC, 1010, False),
        ("accepts", mid(2), SB, 1011, True),
    ]),
    replay_case("sender quota (capacity 48, Q = 3)", 48, 1000, [
        ("commit", mid(1), SB, 1100, 1000, True),
        *[("commit", mid(10 + k), SA, 2000 + k, 1000, True) for k in range(10)],
        ("accepts", mid(1), SB, 1100, False),
        ("accepts", mid(2), SB, 1050, True),
        ("accepts", mid(3), SC, 1001, True),
        ("accepts", mid(30), SA, 2006, False),
        ("accepts", mid(31), SA, 2010, True),
        ("commit", mid(2), SB, 1050, 1000, True),
    ], checks=lambda s: (s["senderHorizons"] == {SA: 2006} and s["horizon"] == 1000) or (_ for _ in ()).throw(AssertionError(s))),
    replay_case("capacity eviction raises only the victim's horizon", 32, 1000, [
        ("commit", mid(1), sender(0), 1005, 1000, True),
        ("commit", mid(2), sender(0), 1005, 1000, True),
        *[("commit", mid(100 + 2 * n + k), sender(n), 1100 + n, 1000, True) for n in range(1, 16) for k in range(2)],
        ("commit", mid(200), sender(16), 1200, 1000, True),
        ("accepts", mid(3), sender(0), 1005, False),
        ("accepts", mid(3), sender(0), 1006, True),
        ("accepts", mid(3), sender(17), 1001, True),
    ], checks=lambda s: (s["senderHorizons"] == {sender(0): 1005} and s["horizon"] == 1000 and len(s["entries"]) == 31)
        or (_ for _ in ()).throw(AssertionError(s))),
    replay_case("sender-horizon compaction folds into H", 2, 1000, [
        ("commit", mid(1), SA, 1010, 1000, True),
        ("commit", mid(2), SA, 1011, 1000, True),
        ("commit", mid(3), SB, 1020, 1000, True),
        ("commit", mid(4), SB, 1021, 1000, True),
        ("commit", mid(5), SC, 1030, 1000, True),
        ("commit", mid(6), SC, 1031, 1000, True),
        ("accepts", mid(7), SA, 1015, False),
        ("accepts", mid(7), SA, 1021, True),
        ("accepts", mid(7), SC, 1030, False),
    ], checks=lambda s: (s["horizon"] == 1020 and s["senderHorizons"] == {SC: 1030}) or (_ for _ in ()).throw(AssertionError(s))),
    replay_case("from_state normalization", 48, None, [
        ("accepts", mid(1), SA, 1002, False),
        ("accepts", mid(20), SC, 1500, True),
    ], initial={
        "version": 1, "horizon": 1000, "senderHorizons": {SC: 900, SB: 1001},
        "entries": [[mid(5), SA, 1005], [mid(1), SA, 1001], [mid(3), SA, 1003], [mid(2), SA, 1002],
                    [mid(4), SA, 1004], [mid(6), SB, 1003]],
    }, checks=lambda s: (s["senderHorizons"] == {SA: 1002, SB: 1001} and len(s["entries"]) == 4)
        or (_ for _ in ()).throw(AssertionError(s))),
]

# =====================================================================================
# signatures
# =====================================================================================

ED_PK = alice.get_signing_public_key()
R, S = alice_sig[:32], int.from_bytes(alice_sig[32:], "little")
IDENTITY = bytes([1]) + bytes(31)
ZERO32 = bytes(32)
P = 2**255 - 19
ed_cases = [
    ("valid", ED_PK, sign_data, alice_sig, True),
    ("S + L", ED_PK, sign_data, R + (S + ED25519_L).to_bytes(32, "little"), False),
    ("S = L", ED_PK, sign_data, R + ED25519_L.to_bytes(32, "little"), False),
    ("non-canonical R (y = p + 3)", ED_PK, sign_data, (P + 3).to_bytes(32, "little") + alice_sig[32:], False),
    ("small-order A (identity), R = identity, S = 0", IDENTITY, sign_data, IDENTITY + ZERO32, False),
    ("small-order A with sign bit set", IDENTITY[:31] + b"\x80", sign_data, IDENTITY + ZERO32, False),
    ("non-canonical A (edff...7f)", bytes.fromhex("ed" + "ff" * 30 + "7f"), sign_data, IDENTITY + ZERO32, False),
    ("wrong message", ED_PK, hashlib.sha256(b"other").digest(), alice_sig, False),
]
bob_sig = bob.sign(sign_data)
r_int, s_int, v = int.from_bytes(bob_sig[:32], "big"), int.from_bytes(bob_sig[32:64], "big"), bob_sig[64]


def secp(r: int, s: int, v: int) -> str:
    return "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + bytes([v]).hex()


BOB_PK = bob.get_signing_public_key()
secp_cases = [
    ("valid", BOB_PK, secp(r_int, s_int, v), True),
    ("high-S (n - s, flipped v)", BOB_PK, secp(r_int, SECP256K1_N - s_int, v ^ 1), False),
    ("v = 2", BOB_PK, secp(r_int, s_int, 2), False),
    ("r = 0", BOB_PK, secp(0, s_int, v), False),
    ("s = 0", BOB_PK, secp(r_int, 0, v), False),
    ("r = n", BOB_PK, secp(SECP256K1_N, s_int, v), False),
    ("uppercase hex", BOB_PK, "0x" + secp(r_int, s_int, v)[2:].upper(), False),
    ("wrong key", carol.get_signing_public_key(), secp(r_int, s_int, v), False),
]


def _secp_ok(pk: bytes, text: str) -> bool:
    import re
    if not re.fullmatch(r"0x[0-9a-f]{130}", text):
        return False
    return verify_signature(sign_data, bytes.fromhex(text[2:]), "secp256k1", pk)


signatures = {"ed25519": [], "secp256k1": []}
for name, pk, data, sig, valid in ed_cases:
    assert verify_signature(data, sig, "ed25519", pk) == valid, name
    signatures["ed25519"].append({"name": name, "publicKey": b64(pk), "signDataHex": data.hex(), "signature": b64(sig), "valid": valid})
for name, pk, text, valid in secp_cases:
    assert _secp_ok(pk, text) == valid, name
    signatures["secp256k1"].append({"name": name, "publicKey": b64(pk), "signDataHex": sign_data.hex(), "signature": text, "valid": valid})

# =====================================================================================
# auth
# =====================================================================================

AUTH_REQUESTS = [
    ({"action": "listen", "since": "-"}, RelayAuthRequest.listen("-")),
    ({"action": "listen", "since": "1773620019899-0"}, RelayAuthRequest.listen("1773620019899-0")),
    ({"action": "inbox", "since": "-", "limit": 100}, RelayAuthRequest.inbox("-", 100)),
    ({"action": "unregister"}, RelayAuthRequest.unregister()),
    # ext as submitted (unsorted keys, non-ASCII, nested): the payload binds its canonical JSON
    # (06 Appendix A form: sorted keys, compact, non-ASCII and '/' unescaped).
    ({"action": "intent", "need": "translate EN to FR", "tags": ["nlp", "fr"],
      "ext": {"urn:example:v1": {"z": [1, {"y": None}], "é": "/ü", "a": True},
              COMMERCE_EXT: {"maxPrice": "10", "currency": "USDC"}}, "ttl": 3600},
     RelayAuthRequest.intent("translate EN to FR", ["nlp", "fr"],
                             {"urn:example:v1": {"z": [1, {"y": None}], "é": "/ü", "a": True},
                              COMMERCE_EXT: {"maxPrice": "10", "currency": "USDC"}}, 3600)),
    ({"action": "intent", "need": "anything", "tags": [], "ttl": 60},
     RelayAuthRequest.intent("anything", [], None, 60)),
    ({"action": "webhook", "method": "PUT", "url": "https://agent.example.com/ace/wake", "secret": "0123456789abcdef0123456789abcdef"},
     RelayAuthRequest.webhook("PUT", "https://agent.example.com/ace/wake", "0123456789abcdef0123456789abcdef")),
    ({"action": "webhook", "method": "GET", "url": "", "secret": ""}, RelayAuthRequest.webhook("GET")),
    ({"action": "webhook", "method": "DELETE", "url": "", "secret": ""}, RelayAuthRequest.webhook("DELETE")),
]
auth_vectors = []
for agent_name, ident in (("alice", alice), ("bob", bob)):
    for request_json, req in AUTH_REQUESTS:
        headers = create_auth_headers(ident, req, TIMESTAMP)
        parsed_auth = parse_auth_headers({k.lower(): v for k, v in headers.items()})
        verify_auth_headers(parsed_auth, req, ace_id=ident.get_ace_id(), scheme=ident.get_signing_scheme(),
                            signing_public_key=ident.get_signing_public_key(), clock=lambda: TIMESTAMP)
        if req.action == "intent":  # the third signed field is the canonical ext (or empty)
            assert encode_payload(ext_canonical(request_json.get("ext"))) in req.payload()
        entry = {"action": req.action, "agent": agent_name, "timestamp": TIMESTAMP, "request": request_json,
                 "payloadHex": req.payload().hex(),
                 "signDataHex": build_sign_data(req.action, ident.get_ace_id(), TIMESTAMP, req.payload()).hex(),
                 "headers": headers}
        if agent_name == "bob":
            entry["verifyOnly"] = True
        auth_vectors.append(entry)

# =====================================================================================
# principal (09): auth sign-data entries, record validation, same-account rules
# =====================================================================================

ACCOUNT = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
OTHER_ACCOUNT = "eip155:8453:0x7a3b00000000000000000000000000000000f91c"
ISSUED = TIMESTAMP - 100
EXPIRES = TIMESTAMP + 30 * 86400
MAX_LIFETIME = 31622400  # 09 § Principal Record: expiresAt - issuedAt <= 366 days
owner_ed = SoftwareIdentity("ed25519", seed("principal-owner-ed25519"), seed("principal-owner-ed25519-enc"))
owner_secp = SoftwareIdentity("secp256k1", seed("principal-owner-secp256k1"), seed("principal-owner-secp256k1-enc"))
attacker_ed = SoftwareIdentity("ed25519", seed("principal-attacker-ed25519"), seed("principal-attacker-ed25519-enc"))
attacker_secp = SoftwareIdentity("secp256k1", seed("principal-attacker-secp256k1"), seed("principal-attacker-secp256k1-enc"))
EIP_ACCOUNT = "eip155:8453:" + owner_secp.get_address()
EIP_ACCOUNT_LOWER = "eip155:8453:" + owner_secp.get_address().lower()
EIP_ACCOUNT_UPPER = "eip155:8453:0x" + owner_secp.get_address()[2:].upper()
assert len({EIP_ACCOUNT, EIP_ACCOUNT_LOWER, EIP_ACCOUNT_UPPER}) == 3  # checksummed, lowercase, uppercase hex


def pkey(ident: SoftwareIdentity) -> PrincipalKey:
    return PrincipalKey(ident.get_signing_scheme(), b64(ident.get_signing_public_key()))


def pkey_json(k: PrincipalKey | None) -> dict | None:
    return None if k is None else {"scheme": k.scheme, "publicKey": k.public_key}


def raw_record(owner: SoftwareIdentity, subject_key: bytes, *, account=ACCOUNT, roles=("controller", "delegate"),
               issued_at=ISSUED, expires_at=EXPIRES, scope="copy:solana,hl") -> dict:
    """Sign without validating (for records that are invalid by construction)."""
    draft = PrincipalRecord(account=account, roles=tuple(roles), signer=pkey(owner),
                            issued_at=issued_at, signature="", expires_at=expires_at, scope=scope)
    sig = owner.sign(principal_sign_data(draft, subject_key))
    return dataclasses.replace(draft, signature=encode_signature(sig, owner.get_signing_scheme())).to_dict()


# auth: action "principal" (signer = the vector agent, subject = the other vector agent). No headers.
for agent_name, ident, subject, scope in (("alice", alice, bob, "copy:solana,hl"), ("alice", alice, bob, None),
                                          ("bob", bob, alice, "copy:solana,hl"), ("bob", bob, alice, None)):
    spk = subject.get_signing_public_key()
    rec = create_principal_record(PrincipalSigner.from_identity(ident), subject_signing_public_key=spk, account=ACCOUNT,
                                  roles=["controller", "delegate"], scope=scope, expires_at=EXPIRES, issued_at=ISSUED)
    validate_principal_record(rec.to_dict(), spk, TIMESTAMP)
    payload_p = principal_payload(rec, spk)
    sd_p = principal_sign_data(rec, spk)
    assert sd_p == build_sign_data("principal", subject.get_ace_id(), ISSUED, payload_p)
    assert payload_p == encode_payload(ACCOUNT, "controller,delegate", rec.signer.scheme, rec.signer.public_key, b64(spk),
                                       scope or "", str(EXPIRES))
    entry = {
        "action": "principal", "agent": agent_name, "timestamp": ISSUED, "now": TIMESTAMP,
        "request": {"account": ACCOUNT, "roles": ["controller", "delegate"], "signerScheme": rec.signer.scheme,
                    "signerPublicKey": rec.signer.public_key, "subjectSigningPublicKey": b64(spk),
                    "subjectAceId": subject.get_ace_id(), "scope": scope, "expiresAt": EXPIRES},
        "subjectSigningPublicKey": b64(spk),
        "payloadHex": payload_p.hex(),
        "signDataHex": sd_p.hex(),
        "signature": rec.signature,
        "record": rec.to_dict(),
    }
    if agent_name == "bob":
        entry["verifyOnly"] = True
    auth_vectors.append(entry)
assert len(auth_vectors) == 22

A_SPK = alice.get_signing_public_key()
BASE = raw_record(owner_ed, A_SPK)
principal_valid_cases = [(name, raw_record(owner, A_SPK, **kw)) for name, owner, kw in (
    ("ed25519 signer, all fields", owner_ed, {}),
    ("secp256k1 signer, all fields", owner_secp, {}),
    ("delegate role only, no scope", owner_ed, {"roles": ("delegate",), "scope": None}),
    ("controller role only", owner_secp, {"roles": ("controller",)}),
    ("issuedAt at now + 300", owner_ed, {"issued_at": TIMESTAMP + 300, "expires_at": TIMESTAMP + 400}),
    ("expiresAt at now + 1", owner_ed, {"expires_at": TIMESTAMP + 1}),
    ("lifetime exactly 31622400 seconds", owner_ed, {"expires_at": ISSUED + MAX_LIFETIME}),
    ("scope of 256 code points", owner_ed, {"scope": "é" * 256}),
)] + [
    # null optional member = absent; unknown members ignored (same signature as the base record)
    ("scope null is absent", raw_record(owner_ed, A_SPK, scope=None) | {"scope": None}),
    ("unknown member ignored", {**BASE, "note": {"x": 1}}),
]
principal_valid = []
for name, rec_d in principal_valid_cases:
    r = validate_principal_record(rec_d, A_SPK, TIMESTAMP)
    principal_valid.append({"name": name, "subjectSigningPublicKey": b64(A_SPK), "record": rec_d,
                            "payloadHex": principal_payload(r, A_SPK).hex(), "signDataHex": principal_sign_data(r, A_SPK).hex()})

principal_invalid_cases = [
    ("not an object", [BASE], A_SPK),
    ("account without account part", mutate(BASE, account="solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"), A_SPK),
    ("account namespace uppercase", mutate(BASE, account="Solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:x"), A_SPK),
    ("account not a string", mutate(BASE, account=1), A_SPK),
    ("account missing", mutate(BASE, account=DELETE), A_SPK),
    ("roles empty", mutate(BASE, roles=[]), A_SPK),
    ("roles out of canonical order", mutate(BASE, roles=["delegate", "controller"]), A_SPK),
    ("roles duplicated", mutate(BASE, roles=["controller", "controller"]), A_SPK),
    ("roles delegate duplicated with controller", mutate(BASE, roles=["controller", "delegate", "delegate"]), A_SPK),
    ("roles unknown", mutate(BASE, roles=["owner"]), A_SPK),
    ("roles legacy value agent", mutate(BASE, roles=["controller", "agent"]), A_SPK),
    ("roles uppercase", mutate(BASE, roles=["Controller"]), A_SPK),
    ("roles not an array", mutate(BASE, roles="controller"), A_SPK),
    ("signer missing", mutate(BASE, signer=DELETE), A_SPK),
    ("signer scheme unknown", mutate(BASE, signer__scheme="p256"), A_SPK),
    ("signer publicKey 31 bytes", mutate(BASE, signer__publicKey=b64(bytes(31))), A_SPK),
    ("signer publicKey non-canonical Base64", mutate(BASE, signer__publicKey=BASE["signer"]["publicKey"][:-2] + "B="), A_SPK),
    ("issuedAt string", mutate(BASE, issuedAt=str(ISSUED)), A_SPK),
    ("issuedAt 1.5", mutate(BASE, issuedAt=1.5), A_SPK),
    ("issuedAt beyond now + 300", raw_record(owner_ed, A_SPK, issued_at=TIMESTAMP + 301, expires_at=TIMESTAMP + 400), A_SPK),
    ("expiresAt missing", mutate(BASE, expiresAt=DELETE), A_SPK),
    ("expiresAt null", mutate(BASE, expiresAt=None), A_SPK),
    ("expiresAt string", mutate(BASE, expiresAt=str(EXPIRES)), A_SPK),
    ("expiresAt equal to issuedAt", raw_record(owner_ed, A_SPK, expires_at=ISSUED), A_SPK),
    ("expiresAt before issuedAt", raw_record(owner_ed, A_SPK, expires_at=ISSUED - 1), A_SPK),
    ("lifetime 31622401 seconds", raw_record(owner_ed, A_SPK, expires_at=ISSUED + MAX_LIFETIME + 1), A_SPK),
    ("expired (expiresAt == now)", raw_record(owner_ed, A_SPK, expires_at=TIMESTAMP), A_SPK),
    ("scope empty", mutate(BASE, scope=""), A_SPK),
    ("scope 257 code points", mutate(BASE, scope="é" * 257), A_SPK),
    ("scope with a control character", mutate(BASE, scope="a\u0007b"), A_SPK),
    ("scope with U+007F", mutate(BASE, scope="a\u007fb"), A_SPK),
    ("scope not a string", mutate(BASE, scope=1), A_SPK),
    ("scope changed after signing", mutate(BASE, scope="copy:solana"), A_SPK),
    ("scope removed after signing", mutate(BASE, scope=DELETE), A_SPK),
    ("expiresAt changed after signing", mutate(BASE, expiresAt=EXPIRES + 1), A_SPK),
    ("roles changed after signing", mutate(BASE, roles=["controller"]), A_SPK),
    ("account changed after signing", mutate(BASE, account=OTHER_ACCOUNT), A_SPK),
    ("signature missing", mutate(BASE, signature=DELETE), A_SPK),
    ("signature in the secp256k1 encoding", mutate(BASE, signature="0x" + "11" * 65), A_SPK),
    ("signature byte flipped", mutate(BASE, signature=flip_b64(BASE["signature"])), A_SPK),
    ("subject mismatch", BASE, bob.get_signing_public_key()),
]
principal_invalid = []
for name, rec_d, subject_key in principal_invalid_cases:
    expect_error(lambda: validate_principal_record(json.loads(json.dumps(rec_d)), subject_key, TIMESTAMP), "invalid_principal")
    principal_invalid.append({"name": name, "subjectSigningPublicKey": b64(subject_key), "record": rec_d,
                              "now": TIMESTAMP, "error": "invalid_principal"})
principal_section = {
    "rules": "validatePrincipalRecord(record, base64decode(subjectSigningPublicKey), now) for every entry; an "
             "entry's own now is authoritative, valid entries (which carry none) use this section's now. Valid "
             "entries also reproduce payloadHex / signDataHex (09 § Signing Context); invalid entries fail with "
             "the error code in error (invalid_principal). "
             "vectors.auth also holds entries with action == \"principal\": they carry no headers, so header "
             "runners skip them; a principal runner checks payloadHex = encodePayload(request.account, "
             "join(request.roles, \",\"), request.signerScheme, request.signerPublicKey, "
             "request.subjectSigningPublicKey, request.scope or \"\", decimal(request.expiresAt)), "
             "signDataHex = buildSignData(\"principal\", request.subjectAceId, timestamp, payload), "
             "validatePrincipalRecord(record, base64decode(subjectSigningPublicKey), now) succeeds (now = the entry's now), "
             "and (unless verifyOnly) "
             "createPrincipalRecord with the agent's signing key, issuedAt = timestamp reproduces record exactly.",
    "account": ACCOUNT, "now": TIMESTAMP, "valid": principal_valid, "invalid": principal_invalid,
}

# principalRules: the receiver is configured per case; senders are identities with a pinned principal.
sender_ids = {
    "controller": SoftwareIdentity("ed25519", seed("pr-controller"), seed("pr-controller-enc")),
    "controller2": SoftwareIdentity("secp256k1", seed("pr-controller2"), seed("pr-controller2-enc")),
    "agent": SoftwareIdentity("secp256k1", seed("pr-agent"), seed("pr-agent-enc")),
    "otherAccount": SoftwareIdentity("ed25519", seed("pr-other"), seed("pr-other-enc")),
    "expired": SoftwareIdentity("ed25519", seed("pr-expired"), seed("pr-expired-enc")),
    "noPrincipal": SoftwareIdentity("ed25519", seed("pr-none"), seed("pr-none-enc")),
    "foreignSubject": SoftwareIdentity("ed25519", seed("pr-foreign"), seed("pr-foreign-enc")),
    "forgedSigner": SoftwareIdentity("ed25519", seed("pr-forged"), seed("pr-forged-enc")),
    "trustedSigner": SoftwareIdentity("ed25519", seed("pr-trusted"), seed("pr-trusted-enc")),
    "eipAgent": SoftwareIdentity("ed25519", seed("pr-eip-agent"), seed("pr-eip-agent-enc")),
    "eipWrongAddress": SoftwareIdentity("ed25519", seed("pr-eip-wrong"), seed("pr-eip-wrong-enc")),
    "eipEd25519Signer": SoftwareIdentity("ed25519", seed("pr-eip-ed"), seed("pr-eip-ed-enc")),
    "eipAgentLowercase": SoftwareIdentity("ed25519", seed("pr-eip-lower"), seed("pr-eip-lower-enc")),
    "eipAgentUppercase": SoftwareIdentity("secp256k1", seed("pr-eip-upper"), seed("pr-eip-upper-enc")),
}
_spk = {k: v.get_signing_public_key() for k, v in sender_ids.items()}
def rule_record(*args, **kw):
    return raw_record(*args, scope=None, **kw)

senders = {
    "controller": rule_record(owner_ed, _spk["controller"], roles=("controller",)),
    "controller2": rule_record(owner_ed, _spk["controller2"], roles=("controller",)),
    "agent": rule_record(owner_ed, _spk["agent"], roles=("delegate",)),
    "otherAccount": rule_record(owner_ed, _spk["otherAccount"], account=OTHER_ACCOUNT),
    "expired": rule_record(owner_ed, _spk["expired"], expires_at=TIMESTAMP),
    "noPrincipal": None,
    "foreignSubject": rule_record(owner_ed, _spk["controller"]),  # issued for the controller's key
    "forgedSigner": rule_record(attacker_ed, _spk["forgedSigner"]),  # same account string, untrusted signer
    "trustedSigner": rule_record(owner_secp, _spk["trustedSigner"]),
    "eipAgent": rule_record(owner_secp, _spk["eipAgent"], account=EIP_ACCOUNT, roles=("delegate",)),
    "eipWrongAddress": rule_record(attacker_secp, _spk["eipWrongAddress"], account=EIP_ACCOUNT, roles=("delegate",)),
    "eipEd25519Signer": rule_record(owner_ed, _spk["eipEd25519Signer"], account=EIP_ACCOUNT, roles=("delegate",)),
    "eipAgentLowercase": rule_record(owner_secp, _spk["eipAgentLowercase"], account=EIP_ACCOUNT_LOWER, roles=("delegate",)),
    "eipAgentUppercase": rule_record(owner_secp, _spk["eipAgentUppercase"], account=EIP_ACCOUNT_UPPER, roles=("delegate",)),
}
SELF_SIGNER = pkey(owner_ed)
CTRL = sender_ids["controller"].get_ace_id()
RQ = "00000000-0000-4000-8000-000000000101"
RQ2 = "00000000-0000-4000-8000-000000000102"
REQ = {"action": "pay", "summary": "Pay 1 USDC", "details": {"payTo": "x"}}
REP = {"action": "x402.pay", "summary": "settled", "outcome": "ok", "proof": {"txHash": "0x1"}}


def dec(rid: str, outcome: str = "approve") -> dict:
    return {"requestId": rid, "outcome": outcome}


def recv(account=ACCOUNT, self_signer=SELF_SIGNER, trusted=()) -> dict:
    return {"selfAccount": account, "selfSigner": self_signer, "trustedSigners": list(trusted)}


OPEN = {RQ: {"to": CTRL, "expiresAt": None}}
WP, BR = "error:wrong_principal", "error:bad_reference"
rule_cases_spec = [
    # (name, receiver, openRequests, steps)
    ("request from a same-account delegate (same signer)", recv(), {}, [("agent", "request", REQ, "ok")]),
    ("report from a same-account delegate", recv(), {}, [("agent", "report", REP, "ok")]),
    ("report from a same-account controller (either direction)", recv(), {}, [("controller", "report", REP, "ok")]),
    ("request from a controller (no role check)", recv(), {}, [("controller", "request", REQ, "ok")]),
    ("receiver without principal", recv(account=None), {}, [("agent", "request", REQ, WP)]),
    ("sender without principal", recv(), {}, [("noPrincipal", "request", REQ, WP)]),
    ("sender principal expired", recv(), {}, [("expired", "report", REP, WP)]),
    ("sender principal issued for another subject", recv(), {}, [("foreignSubject", "request", REQ, WP)]),
    ("signer binding: same account string, untrusted signer", recv(), {}, [("forgedSigner", "request", REQ, WP)]),
    ("signer binding: no selfSigner fails closed", recv(self_signer=None), {}, [("agent", "request", REQ, WP)]),
    ("signer binding: trusted-signer set", recv(trusted=[pkey(owner_secp)]), {}, [("trustedSigner", "request", REQ, "ok")]),
    ("signer binding: signer outside the trusted-signer set", recv(trusted=[pkey(attacker_secp)]), {},
     [("trustedSigner", "request", REQ, WP)]),
    ("signer binding: eip155 address derivation", recv(account=EIP_ACCOUNT, self_signer=None), {},
     [("eipAgent", "request", REQ, "ok")]),
    ("signer binding: eip155 lowercase account address (case-insensitive)",
     recv(account=EIP_ACCOUNT_LOWER, self_signer=None), {}, [("eipAgentLowercase", "request", REQ, "ok")]),
    ("signer binding: eip155 uppercase-hex account address (case-insensitive)",
     recv(account=EIP_ACCOUNT_UPPER, self_signer=None), {}, [("eipAgentUppercase", "report", REP, "ok")]),
    ("signer binding: eip155 address mismatch", recv(account=EIP_ACCOUNT, self_signer=None), {},
     [("eipWrongAddress", "request", REQ, WP)]),
    ("signer binding: eip155 with an ed25519 signer", recv(account=EIP_ACCOUNT, self_signer=None), {},
     [("eipEd25519Signer", "request", REQ, WP)]),
    ("sender of another account", recv(), {}, [("otherAccount", "request", REQ, WP)]),
    ("decision from the request's controller", recv(), OPEN, [("controller", "decision", dec(RQ), "ok")]),
    ("decision from a non-controller", recv(), OPEN, [("agent", "decision", dec(RQ), WP)]),
    ("role check precedes the request check", recv(), OPEN,
     [("agent", "decision", dec("00000000-0000-4000-8000-000000000999"), WP)]),
    ("decision referencing no request", recv(), OPEN,
     [("controller", "decision", dec("00000000-0000-4000-8000-000000000999"), BR)]),
    ("decision for an expired request", recv(), {RQ: {"to": CTRL, "expiresAt": TIMESTAMP - 1}},
     [("controller", "decision", dec(RQ), BR)]),
    ("decision at the request's expiry second", recv(), {RQ: {"to": CTRL, "expiresAt": TIMESTAMP}},
     [("controller", "decision", dec(RQ), "ok")]),
    ("second decision for the same request", recv(), OPEN,
     [("controller", "decision", {**dec(RQ), "result": {"x402": "payload"}}, "ok"),
      ("controller", "decision", dec(RQ, "deny"), BR)]),
    ("decision from a controller the request was not sent to", recv(), OPEN,
     [("controller2", "decision", dec(RQ), WP), ("controller", "decision", dec(RQ, "deny"), "ok")]),
    ("decisions for two open requests", recv(), {**OPEN, RQ2: {"to": sender_ids["controller2"].get_ace_id(), "expiresAt": None}},
     [("controller2", "decision", dec(RQ2), "ok"), ("controller", "decision", dec(RQ), "ok"),
      ("controller2", "decision", dec(RQ2, "deny"), BR)]),
    ("decision to a receiver without principal", recv(account=None), OPEN, [("controller", "decision", dec(RQ), WP)]),
]
rule_cases = []
for name, receiver, open_map, steps in rule_cases_spec:
    open_ = dict(open_map)
    out_steps = []
    for sname, t, body, expect in steps:
        def to_of(c: str, r: str, now: int, open_=open_) -> str | None:
            e = open_.get(r) if c == conversation_id else None
            return None if e is None or (e["expiresAt"] is not None and now > e["expiresAt"]) else e["to"]

        def go(sname=sname, t=t, body=body):
            decode_body(t, j(body).encode())
            check_principal_rules(t, body, conversation_id=conversation_id, sender_principal=senders[sname],
                                  sender_signing_public_key=_spk[sname], self_account=receiver["selfAccount"],
                                  open_request_to=to_of, now=TIMESTAMP, self_signer=receiver["selfSigner"],
                                  trusted_signers=frozenset(receiver["trustedSigners"]))
            return "ok"
        got = outcome(go)
        assert got == expect, f"principalRules {name}: expected {expect}, got {got}"
        if got == "ok" and t == "decision":
            del open_[body["requestId"]]
        out_steps.append({"sender": sname, "type": t, "body": body, "expect": expect})
    rule_cases.append({"name": name, "now": TIMESTAMP, "selfAccount": receiver["selfAccount"],
                       "selfSigner": pkey_json(receiver["selfSigner"]),
                       "trustedSigners": [pkey_json(k) for k in receiver["trustedSigners"]],
                       "openRequests": open_map, "steps": out_steps})
principal_rules = {
    "rules": "09 § Same-Account Rules. For each case keep a map of open requests (initially openRequests: "
             "requestId -> {to, expiresAt}). For each step call checkPrincipalRules(type, body, conversationId, "
             "senders[sender].principal, base64decode(senders[sender].signingPublicKey), selfAccount, "
             "openRequestTo, now, selfSigner, trustedSigners), where openRequestTo(c, r, now) returns open[r].to when "
             "c == conversationId, r is in the map and (expiresAt is null or now <= expiresAt), else null. "
             "expect is 'ok' (no error) or 'error:<code>' (the ACE error code); an accepted decision removes "
             "body.requestId from the map. Each case's now is authoritative (the section-level now is the default "
             "for a case that omits it). selfAccount null = the "
             "receiver has no principal; selfSigner null and trustedSigners [] = no authority keys besides eip155 "
             "address derivation. Every body passes validateBody. Sender labels are fixture names: 'agent' "
             "and the eip* senders carry the delegate role, 'controller*' the controller role.",
    "now": TIMESTAMP, "conversationId": conversation_id, "account": ACCOUNT,
    "senders": {k: {"aceId": sender_ids[k].get_ace_id(), "signingPublicKey": b64(_spk[k]), "principal": senders[k]}
                for k in sender_ids},
    "cases": rule_cases,
}

# =====================================================================================
# registrations
# =====================================================================================

PROFILE_EXT = {
    "urn:example:v1": {"z": [1, {"y": None}], "é": "/ü", "a": True},  # opaque namespace, unsorted keys
    COMMERCE_EXT: {"chains": ["eip155:8453"], "pricing": {"currency": "USDC", "maxAmount": "12.50"},
                   "settlement": ["crypto/instant"], "accounts": [{"network": "eip155:8453", "address": "0x7a3b"}]},
}
PROFILE = AgentProfile(name="Agent α", description="中文 / quote \"", image="https://example.com/a.png",
                       tags=["data", "defi"], capabilities=["translate"], endpoint="https://example.com/ace",
                       ext=PROFILE_EXT)
_KEEP = object()
registration_vectors = []
for name, ident in (("alice", alice), ("bob", bob)):
    for mode in ("keep", "remove", "replace"):
        prof = _KEEP if mode == "keep" else None if mode == "remove" else PROFILE
        request = create_registration_request(ident, timestamp=TIMESTAMP) if prof is _KEEP else \
            create_registration_request(ident, prof, timestamp=TIMESTAMP)
        payload = registration_payload(request["encryptionPublicKey"], request["signingPublicKey"], request["scheme"],
                                       SDK_KEEP if prof is _KEEP else prof)
        sd = build_sign_data("register-request", request["aceId"], TIMESTAMP, payload)
        verified = verify_registration_request(json.loads(json.dumps(request)), clock=lambda: TIMESTAMP)
        assert verified.request_digest == hashlib.sha256(sd).hexdigest()
        registration_vectors.append({"agent": name, "mode": mode, "now": TIMESTAMP, "request": request,
                                     "payloadHex": payload.hex(), "signDataHex": sd.hex(),
                                     "requestDigest": verified.request_digest})


def payload_fields(payload: bytes) -> list[bytes]:
    """Split an encodePayload byte string (four-byte big-endian length prefixes)."""
    out, i = [], 0
    while i < len(payload):
        n = int.from_bytes(payload[i:i + 4], "big")
        out.append(payload[i + 4:i + 4 + n])
        i += 4 + n
    assert i == len(payload)
    return out


# 02 § Registration authorization: replace = 4 + 16 fields after the three key fields and mode (name, description,
# image, tags, capabilities, endpoint, canonical ext or empty, present|absent, 8 principal fields); principal group
# absent -> "absent" + 8 empty strings.
_pa = payload_fields(registration_payload(b64(alice.get_encryption_public_key()), b64(A_SPK), "ed25519", PROFILE))
assert len(_pa) == 4 + 16 and _pa[3] == b"replace" and _pa[-9] == b"absent" and _pa[-8:] == [b""] * 8
assert _pa[10] == canonical_state_bytes(PROFILE_EXT) == ext_canonical(PROFILE_EXT).encode()
assert payload_fields(registration_payload("e", "s", "ed25519", AgentProfile(name="A")))[10] == b""
assert registration_vectors[2]["request"]["profile"]["ext"] == json.loads(canonical_state_bytes(PROFILE_EXT))
PRINCIPAL_P = raw_record(owner_ed, A_SPK)
PROFILE_P = dataclasses.replace(PROFILE, principal=PrincipalRecord.from_dict(PRINCIPAL_P))
_req_p = create_registration_request(alice, PROFILE_P, timestamp=TIMESTAMP)
assert _req_p["profile"]["principal"] == PRINCIPAL_P
_payload_p = registration_payload(_req_p["encryptionPublicKey"], _req_p["signingPublicKey"], _req_p["scheme"], PROFILE_P)
_pp = payload_fields(_payload_p)
assert len(_pp) == 4 + 16 and _pp[-9:] == [b"present", PRINCIPAL_P["account"].encode(), b"controller,delegate",
                                            b"ed25519", PRINCIPAL_P["signer"]["publicKey"].encode(),
                                            str(ISSUED).encode(), str(EXPIRES).encode(), b"copy:solana,hl",
                                            PRINCIPAL_P["signature"].encode()]
_sd_p = build_sign_data("register-request", _req_p["aceId"], TIMESTAMP, _payload_p)
_ver_p = verify_registration_request(json.loads(json.dumps(_req_p)), clock=lambda: TIMESTAMP)
assert _ver_p.request_digest == hashlib.sha256(_sd_p).hexdigest() and _ver_p.peer.principal is not None
registration_vectors.append({"agent": "alice", "mode": "replace-principal", "now": TIMESTAMP, "request": _req_p,
                             "payloadHex": _payload_p.hex(), "signDataHex": _sd_p.hex(),
                             "requestDigest": _ver_p.request_digest})


def manual_request(ident: SoftwareIdentity, *, enc: bytes | None = None, ts: int = TIMESTAMP, profile=_KEEP,
                   binding_ts: int | None = None, auth_profile: object = ...) -> tuple[dict, bytes]:
    """Return the request and the registration payload its authorization signs."""
    epk = b64(enc if enc is not None else ident.get_encryption_public_key())
    spk = b64(ident.get_signing_public_key())
    scheme = ident.get_signing_scheme()
    sig = ident.sign(build_sign_data("register", ident.get_ace_id(), binding_ts if binding_ts is not None else ts,
                                     encode_payload(epk, spk)))
    ap = profile if auth_profile is ... else auth_profile  # default (...): authorize what is sent
    ap_obj = SDK_KEEP if ap is _KEEP else None if ap is None else AgentProfile.from_dict(ap)
    auth_payload = registration_payload(epk, spk, scheme, ap_obj)
    auth = ident.sign(build_sign_data("register-request", ident.get_ace_id(), ts, auth_payload))
    req = {"aceId": ident.get_ace_id(), "encryptionPublicKey": epk, "signingPublicKey": spk, "scheme": scheme,
           "timestamp": ts, "signature": encode_signature(sig, scheme), "authorization": encode_signature(auth, scheme)}
    if profile is not _KEEP:
        req["profile"] = profile
    return req, auth_payload


_r, _r_payload = manual_request(alice)
registration_errors = [
    ("aceId does not match signingPublicKey", {**_r, "aceId": B}, _r_payload, TIMESTAMP, "invalid_registration"),
    ("missing authorization", {k: v for k, v in _r.items() if k != "authorization"}, None, TIMESTAMP, "invalid_registration"),
    ("timestamp outside the window", _r, _r_payload, TIMESTAMP + 301, "stale_timestamp"),
    ("encryption key of 1215 bytes", *manual_request(alice, enc=alice.get_encryption_public_key()[:1215]), TIMESTAMP, "invalid_key"),
    ("profile commerce ext pricing with an extra field",
     *manual_request(alice, profile={"name": "A", "ext": {COMMERCE_EXT: {"pricing": {"currency": "USDC", "extra": "1"}}}},
                    auth_profile=None),  # the profile stage fails before the signatures are checked
     TIMESTAMP, "invalid_profile"),
    ("profile ext key not a namespaced identifier",
     *manual_request(alice, profile={"name": "A", "ext": {"pricing": {"currency": "USDC"}}}, auth_profile=None),
     TIMESTAMP, "invalid_profile"),
    ("profile ext value not an object",
     *manual_request(alice, profile={"name": "A", "ext": {"urn:example:v1": "x"}}, auth_profile=None),
     TIMESTAMP, "invalid_profile"),
    ("authorization over a different ext",  # same keys, one value changed after signing
     *manual_request(bob, profile={"name": "A", "ext": {"urn:example:v1": {"a": 1}}},
                    auth_profile={"name": "A", "ext": {"urn:example:v1": {"a": 2}}}),
     TIMESTAMP, "invalid_authorization"),
    ("binding signature over another timestamp", *manual_request(bob, binding_ts=TIMESTAMP - 1), TIMESTAMP, "invalid_signature"),
    ("authorization for another mutation", *manual_request(bob, profile=None, auth_profile=_KEEP), TIMESTAMP, "invalid_authorization"),
    ("profile principal issued for another subject",
     *manual_request(alice, profile={"name": "A", "principal": raw_record(owner_ed, bob.get_signing_public_key())}),
     TIMESTAMP, "invalid_principal"),
    ("profile principal with roles out of order",
     *manual_request(alice, profile={"name": "A", "principal": {**raw_record(owner_ed, A_SPK), "roles": ["delegate", "controller"]}}),
     TIMESTAMP, "invalid_principal"),
    ("profile principal expired",
     *manual_request(alice, profile={"name": "A", "principal": raw_record(owner_ed, A_SPK, expires_at=TIMESTAMP)}),
     TIMESTAMP, "invalid_principal"),
    ("profile principal not an object",
     *manual_request(alice, profile={"name": "A", "principal": "x"}, auth_profile=None),
     TIMESTAMP, "invalid_principal"),
    ("profile principal without expiresAt",
     *manual_request(alice, profile={"name": "A", "principal": {k: v for k, v in raw_record(owner_ed, A_SPK).items()
                                                               if k != "expiresAt"}}, auth_profile=None),
     TIMESTAMP, "invalid_principal"),
]
verify_registration_request(_r, clock=lambda: TIMESTAMP + 300)  # the window bound is inclusive
registration_error_vectors = []
for name, req, signed_payload, now, code in registration_errors:
    expect_error(lambda: verify_registration_request(json.loads(json.dumps(req)), clock=lambda: now), code)
    registration_error_vectors.append({"name": name, "now": now, "request": req,
                                       "payloadHex": None if signed_payload is None else signed_payload.hex(), "error": code})

# =====================================================================================
# urls / base64
# =====================================================================================

URLS = [
    ("https://example.com", True), ("https://example.com/", True), ("https://a.b-c.example.com:8443/p/a?q=1&r=%20#frag", True),
    ("https://example.com?x=1", True), ("https://example.com#top", True), ("https://1.2.3.4/x", True),
    ("https://example.com:65535", True), ("https://example.com:1", True), ("https://localhost", True),
    ("https://" + "a" * 63 + ".com", True), ("https://" + "a" * 64 + ".com", False),
    ("HTTPS://example.com", False), ("Https://example.com", False), ("http://example.com", False),
    ("https://user@example.com", False), ("https://user:pw@example.com/", False),
    ("https://[::1]/", False), ("https://[2001:db8::1]:443/", False),
    ("https://example.com:0", False), ("https://example.com:65536", False), ("https://example.com:", False),
    ("https://exa mple.com", False), ("https://example.com/a b", False), ("https://example.com.", False),
    ("https://example.com./", False), ("https://-example.com", False), ("https://example-.com", False),
    ("https://", False), ("https:///path", False), ("https://exämple.com", False), ("https://example.com/\n", False),
    ("https://example.com\\path", False), ("https://example.com/\"q\"", False),
]
url_vectors = []
for url, valid in URLS:
    assert is_https_url(url) == valid, url
    url_vectors.append({"url": url, "valid": valid})
host253 = ".".join(["a" * 63] * 3 + ["a" * 61])
host255 = ".".join(["a" * 63] * 4)
for url, valid in [("https://" + host253, True), ("https://" + host255 + "/", False)]:
    assert len(url.split("//")[1].rstrip("/")) in (253, 255)
    assert is_https_url(url) == valid
    url_vectors.append({"url": url, "valid": valid})
base = "https://example.com/"
for total, valid in [(2048, True), (2049, False)]:
    url = base + "a" * (total - len(base))
    assert len(url) == total and is_https_url(url) == valid
    url_vectors.append({"url": url, "valid": valid})

B64 = [
    ("", True), ("QQ==", True), ("QR==", False), ("QUI=", True), ("QUJ=", False), ("QUJD", True),
    ("+/8=", True), ("-_8=", False), ("QQ", False), ("QQ=", False), ("QUJD====", False), ("QUJD\n", False),
    (" QUJD", False), ("QU JD", False), ("QUJDRA==", True), ("QUJDRB==", False), ("QUJDRA=", False), ("=QUJD", False),
]
base64_vectors = []
for text, valid in B64:
    try:
        raw = from_base64(text)
        got = True
    except ACEError:
        got = False
    assert got == valid, text
    entry = {"text": text, "valid": valid}
    if valid:
        entry["hex"] = raw.hex()
    base64_vectors.append(entry)

# =====================================================================================
# peerBinding (rollback barrier)
# =====================================================================================

alice_alt_enc = SoftwareIdentity("ed25519", seed("alice-signing"), seed("alice-encryption-2"))
alice_alt_enc3 = SoftwareIdentity("ed25519", seed("alice-signing"), seed("alice-encryption-3"))
assert alice_alt_enc.get_ace_id() == A


def record(ident: SoftwareIdentity, registered_at: int, *, tamper: bool = False) -> dict:
    req = create_registration_request(ident, timestamp=registered_at)
    sig = flip_b64(req["signature"]) if tamper else req["signature"]
    return {"aceId": req["aceId"], "scheme": req["scheme"], "encryptionPublicKey": req["encryptionPublicKey"],
            "signingPublicKey": req["signingPublicKey"], "registrationSignature": sig, "registeredAt": registered_at}


def reg_file(ident: SoftwareIdentity, ts: int = TIMESTAMP) -> dict:
    return create_registration_file(ident, name="Alice", endpoint="https://alice.example/ace", timestamp=ts).to_dict()


def binding_case(name: str, now: int, steps: list[tuple]) -> dict:
    pin = None
    out = []
    for step in steps:
        kind, data, expect = step
        def go():
            nonlocal pin
            cand = verify_peer_record(data) if kind == "record" else verify_registration_file(data)
            new_pin, result = adopt_decision(pin, cand, now)
            pin = new_pin
            return result
        got = outcome(go)
        assert got == expect, f"peerBinding {name}: expected {expect}, got {got}"
        entry = {"record": data} if kind == "record" else {"registrationFile": data}
        entry["expect"] = expect
        if pin is not None and not got.startswith("error"):
            entry["pinRegisteredAt"] = pin.registered_at
            entry["pinEncryptionPublicKey"] = b64(pin.encryption_public_key)
        out.append(entry)
    return {"name": name, "now": now, "sequence": out}


NOW = TIMESTAMP
peer_binding = [
    binding_case("same key keeps the highest registeredAt", NOW, [
        ("record", record(alice, NOW - 100), "adopted"),
        ("record", record(alice, NOW - 50), "unchanged"),
        ("record", record(alice, NOW - 200), "unchanged"),
    ]),
    binding_case("rotation requires a strictly newer binding", NOW, [
        ("record", record(alice, NOW - 100), "adopted"),
        ("record", record(alice_alt_enc, NOW - 101), "error:stale_peer_binding"),
        ("record", record(alice_alt_enc, NOW - 100), "error:stale_peer_binding"),
        ("record", record(alice_alt_enc, NOW - 99), "rotated"),
        ("record", record(alice, NOW - 99), "error:stale_peer_binding"),
        ("record", record(alice_alt_enc3, NOW), "rotated"),
    ]),
    binding_case("future registeredAt bound", NOW, [
        ("record", record(alice, NOW + 300), "adopted"),
        ("record", record(alice_alt_enc, NOW + 301), "error:invalid_peer"),
    ]),
    binding_case("bad binding signature", NOW, [
        ("record", record(alice, NOW, tamper=True), "error:invalid_peer"),
        ("record", record(alice, NOW), "adopted"),
    ]),
    binding_case("signed registration file rotates a relay pin", NOW, [
        ("record", record(alice, NOW - 100), "adopted"),
        ("registrationFile", reg_file(alice_alt_enc), "rotated"),
        ("registrationFile", reg_file(alice, NOW - 1), "error:stale_peer_binding"),
    ]),
    binding_case("relay binding rotates a registration-file pin", NOW, [
        ("registrationFile", reg_file(alice, NOW - 100), "adopted"),
        ("record", record(alice_alt_enc, NOW - 100), "error:stale_peer_binding"),
        ("record", record(alice_alt_enc, NOW - 99), "rotated"),
    ]),
]

# Salted private commitments; tree hashes are independently reconstructed here.

audit_openings = [{"statementHex": f"statement {i} 你好".encode().hex(),
                   "saltHex": seed(f"audit salt {i}").hex()} for i in range(9)]
for opening in audit_openings:
    opening["commitment"] = audit_commitment(bytes.fromhex(opening["statementHex"]), bytes.fromhex(opening["saltHex"]))
audit_commitments = [o["commitment"] for o in audit_openings]
audit_tree = AuditTree(audit_commitments)
def audit_root(cs):
    if not cs:
        return hashlib.sha256(b"").hexdigest()
    if len(cs) == 1:
        return hashlib.sha256(b"\x00" + bytes.fromhex(cs[0])).hexdigest()
    cut = 1 << ((len(cs) - 1).bit_length() - 1)
    return hashlib.sha256(b"\x01" + bytes.fromhex(audit_root(cs[:cut])) + bytes.fromhex(audit_root(cs[cut:]))).hexdigest()
audit_roots = [audit_root(audit_commitments[:n]) for n in range(10)]
assert audit_roots == [audit_tree.root(n) for n in range(10)]
audit_vectors = {
    "openings": audit_openings, "roots": audit_roots,
    "inclusions": [{"index": i, "size": n, "proof": audit_tree.inclusion(i, n)} for n in range(1, 10) for i in range(n)],
    "consistencies": [{"first": m, "second": n, "proof": audit_tree.consistency(m, n)} for n in range(10) for m in range(n + 1)],
}
audit_checkpoints = {"alice": create_audit_checkpoint(audit_tree, MESSAGE_ID, alice, TIMESTAMP),
                     "bob": create_audit_checkpoint(audit_tree, MESSAGE_ID, bob, TIMESTAMP)}
audit_vectors["checkpoints"] = [c.to_dict() for c in audit_checkpoints.values()]
audit_vectors["witnesses"] = []
for operator_name, operator, witness_name, witness in [("alice", alice, "bob", bob), ("bob", bob, "alice", alice)]:
    checkpoint = audit_checkpoints[operator_name]
    trusted_operator = verify_registration_file(create_registration_file(operator, name=operator_name, endpoint="https://example.org/ace", timestamp=TIMESTAMP))
    receipt = create_audit_witness_receipt(checkpoint, trusted_operator, witness, TIMESTAMP + 1)
    expected_digest = build_sign_data("audit", operator.get_ace_id(), TIMESTAMP,
        encode_payload(MESSAGE_ID, str(audit_tree.size), bytes.fromhex(audit_tree.root()))).hex()
    assert audit_checkpoint_digest(checkpoint) == expected_digest
    audit_vectors["witnesses"].append({"operator": operator_name, "witness": witness_name,
        "checkpoint": checkpoint.to_dict(), "checkpointDigest": expected_digest, "receipt": receipt.to_dict()})

EXECUTOR = B
execution_intent = {"operationId": MESSAGE_ID, "audience": EXECUTOR, "resource": "urn:example:resource:1",
                    "action": "urn:example:transfer:1", "schemaDigest": "ab" * 32, "details": {"recipient": "你好", "amount": "5"},
                    "expiresAt": 200}
intent_hash = execution_intent_digest(execution_intent)
def grant(signer, subject, id, parent=None, depth=1, **changes):
    c = {"grantId": f"00000000-0000-4000-8000-{id:012d}", "issuer": signer.get_ace_id(), "subject": subject,
         "audience": EXECUTOR, "resource": execution_intent["resource"], "intentDigest": intent_hash,
         "issuedAt": 100, "expiresAt": 300, "epoch": 1, "parent": parent, "delegationDepth": depth, **changes}
    return create_execution_grant(signer, c)
grant_root = grant(alice, B, 1)
grant_child = grant(bob, A, 2, execution_grant_digest(grant_root), 0)
grant_authority = verify_registration_file(create_registration_file(alice, name="Alice", endpoint="https://example.org/ace"))
grant_cases = []
def grant_case(name, chain=None, intent=None, sender=A, executor=EXECUTOR, epoch=1, revoked=None, now=150, expected="ok"):
    case = {"name": name, "chain": chain if chain is not None else [grant_root, grant_child], "intent": intent or execution_intent,
            "sender": sender, "executor": executor, "epoch": epoch, "revoked": revoked or [], "now": now, "expected": expected}
    got = outcome(lambda: verify_execution_grant_chain(case["chain"], case["intent"], sender, executor,
        ResourcePolicy(execution_intent["resource"], grant_authority, epoch, tuple(case["revoked"])), now))
    assert got == (intent_hash if expected == "ok" else "error:" + expected), (name, expected, got)
    grant_cases.append(case)
grant_case("delegated across signature schemes")
grant_case("direct root capability", chain=[grant_root], sender=B)
for name, options in [
    ("wrong authenticated sender", {"sender": B}), ("wrong executor", {"executor": A}),
    ("stale policy epoch", {"epoch": 2}), ("revoked ancestor", {"revoked": [grant_root["claims"]["grantId"]]}),
    ("revoked leaf", {"revoked": [grant_child["claims"]["grantId"]]}), ("absolute deadline", {"now": 200}),
    ("not yet issued", {"now": 99}), ("changed effect", {"intent": {**execution_intent, "details": {**execution_intent["details"], "amount": "6"}}}),
    ("unsigned constraint", {"intent": {**execution_intent, "extra": True}}),
    ("noncanonical unicode field", {"intent": {**execution_intent, "details": {"e\u0301": "ambiguous"}}}), ("empty chain", {"chain": []}),
    ("wrong root authority", {"chain": [grant(bob, A, 5)]}),
    ("missing parent link", {"chain": [grant_child]}),
    ("wrong parent hash", {"chain": [grant_root, grant(bob, A, 2, "cd" * 32, 0)]}),
    ("delegation not attenuated", {"chain": [grant_root, grant(bob, A, 2, execution_grant_digest(grant_root), 1)]}),
    ("expiry broadened", {"chain": [grant_root, grant(bob, A, 2, execution_grant_digest(grant_root), 0, expiresAt=301)]}),
    ("parent cannot delegate", {"chain": [grant(alice, B, 1, depth=0), grant_child]}),
    ("different resource", {"chain": [grant(alice, A, 1, resource="urn:example:resource:2")]}),
    ("duplicate grant IDs", {"chain": [grant_root, grant(bob, A, 1, execution_grant_digest(grant_root), 0)]}),
]:
    grant_case(name, expected="invalid_authorization", **options)
grant_vectors = {"intentDigest": intent_hash, "rootDigest": execution_grant_digest(grant_root), "cases": grant_cases}

# =====================================================================================
# output
# =====================================================================================

vectors = {
    "version": "4",
    "agents": {"alice": agent_json(alice), "bob": agent_json(bob)},
    "xwing": XWING_VECTORS,
    "vectors": {
        "audit": audit_vectors,
        "grants": grant_vectors,
        "aceKemSalt": ACE_KEM_SALT.hex(),
        "conversationId": conversation_id,
        "signData": {
            "action": "packet",
            "aceId": A,
            "timestamp": TIMESTAMP,
            "messagePayload": {
                "to": B, "conversationId": conversation_id, "messageId": MESSAGE_ID,
                "kemCiphertext": b64(KEM_CIPHERTEXT), "ciphertext": b64(CIPHERTEXT),
            },
            "signDataHex": sign_data.hex(),
        },
        "signature": {"scheme": "ed25519", "signDataHex": sign_data.hex(), "signatureValue": encode_signature(alice_sig, "ed25519")},
        "encryptedMessage": {"from": "alice", "to": "bob", "envelope": envelope, "expectedBody": EXPECTED_BODY},
        "envelopes": envelope_vectors,
        "bodies": body_vectors,
        "transitions": transitions,
        "replay": replay_vectors,
        "signatures": signatures,
        "auth": auth_vectors,
        "registrations": registration_vectors,
        "registrationErrors": registration_error_vectors,
        "urls": url_vectors,
        "base64": base64_vectors,
        "peerBinding": peer_binding,
        "principal": principal_section,
        "principalRules": principal_rules,
        **client_vectors(),
    },
}

with open(OUT, "w", encoding="utf-8") as f:
    json.dump(vectors, f, indent=2)
    f.write("\n")

print(f"Generated {OUT}")
for section in ("envelopes", "bodies", "replay", "auth", "registrations", "registrationErrors", "urls", "base64", "peerBinding"):
    print(f"  {section}: {len(vectors['vectors'][section])}")
print(f"  principal: {len(principal_valid)} valid, {len(principal_invalid)} invalid; principalRules: {len(rule_cases)} cases")
print(f"  transitions: {len(cases)} cases, matrix {len(matrix)}x{len(ECONOMIC)}x2")
for section in ("webhooks", "relayUrls", "blockedAddresses", "relayErrors", "directReceive"):
    print(f"  {section}: {len(vectors['vectors'][section]['cases'])}")
