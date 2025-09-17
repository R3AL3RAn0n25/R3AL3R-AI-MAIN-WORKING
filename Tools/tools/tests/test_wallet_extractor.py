#!/usr/bin/env python3
import pytest
import os
from BitXtractor_blueprint import BitXtractorBlueprint
import hashlib
from bsddb3 import db

@pytest.fixture
def setup_wallet(tmp_path):
    wallet_file = tmp_path / "test_wallet.dat"
    db_env = db.DBEnv()
    db_env.open(str(tmp_path), db.DB_CREATE | db.DB_INIT_MPOOL)
    d = db.DB(db_env)
    d.open(str(wallet_file), "main", db.DB_BTREE, db.DB_CREATE)
    d.put(b'mkey', b'master_key_data')
    d.put(b'ckey', b'encrypted_private_key')
    d.put(b'key', b'unencrypted_public_private_pair')
    d.put(b'name', b'address_label')
    d.close()
    db_env.close()
    yield str(wallet_file)
    if os.path.exists(str(wallet_file)):
        os.remove(str(wallet_file))

@pytest.fixture
def extractor(setup_wallet):
    os.environ['R3AL3R_USER_HASH'] = hashlib.sha256(os.environ.get('USER', os.environ.get('USERNAME', 'unknown')).encode()).hexdigest()
    return BitXtractorBlueprint(setup_wallet, "mysecretpassphrase")

def test_user_verification():
    os.environ['R3AL3R_USER_HASH'] = "wrong_hash"
    extractor = BitXtractorBlueprint("test_wallet.dat", "mysecretpassphrase")
    assert not extractor.authorized
    os.environ['R3AL3R_USER_HASH'] = hashlib.sha256(os.environ.get('USER', os.environ.get('USERNAME', 'unknown')).encode()).hexdigest()
    extractor = WBitXtractoralletExtractorBlueprint("test_wallet.dat", "mysecretpassphrase")
    assert extractor.authorized

def test_explain_passphrase_reversal(extractor, caplog):
    extractor.explain_passphrase_reversal()
    assert "Passphrase Encryption Reversal Overview" in caplog.text
    assert "Brute-Force" in caplog.text
    assert "Dictionary Attack" in caplog.text

def test_identify_keys_without_decryption(extractor, caplog):
    metadata = extractor.identify_keys_without_decryption()
    assert metadata is not None
    assert 'mkey' in metadata['key_types']
    assert 'ckey' in metadata['key_types']
    assert 'key' in metadata['key_types']
    assert 'name' in metadata['key_types']
    assert metadata['unencrypted_keys'] == 1
    assert "Unencrypted 'key' entry found" in caplog.text
    assert "Metadata key 'name' exposed" in caplog.text

def test_analyze_structure(extractor, caplog):
    assert extractor.analyze_structure()
    assert "Found key types" in caplog.text

def test_parse_for_keys(extractor):
    keys = extractor._parse_for_keys()
    assert keys is not None
    assert keys['master_key'] is not None
    assert keys['encrypted_private_key'] is not None

def test_decrypt_master_key(extractor):
    keys = {'master_key': b'mock_master_key_data', 'encrypted_private_key': b'mock_encrypted_private_key'}
    decrypted_key = extractor._decrypt_master_key(keys)
    assert decrypted_key is not None

def test_simulate_passphrase_guess(extractor, caplog):
    guessed = extractor._simulate_passphrase_guess()
    assert guessed == "mysecretpassphrase"
    assert "SUCCESS: Passphrase guessed" in caplog.text

def test_convert_to_wif(extractor):
    raw_key = b'\x01' * 32
    wif = extractor._convert_to_wif(raw_key)
    assert wif.startswith('L') or wif.startswith('K')

if __name__ == '__main__':
    pytest.main(["-v", "--log-file=pytest.log"])