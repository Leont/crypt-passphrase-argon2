#!perl

use strict;
use warnings;

use Test::More;

use lib 't/lib';
use Crypt::Passphrase::Argon2::Rot;

my $passphrase = Crypt::Passphrase::Argon2::Rot->new(
	profile => 'interactive',
	active  => 12,
);

my $password = 'password';
my $salt = "\0" x 16;

my $hash1 = $passphrase->hash_password($password);
ok($passphrase->verify_password($password, $hash1), 'Self-generated password validates');
ok(!$passphrase->needs_rehash($hash1), 'Self-generated password doesn\'t need to be regenerated');

my $passphrase2 = Crypt::Passphrase::Argon2::Rot->new(
	profile => 'interactive',
	active  => 42,
);
ok($passphrase2->verify_password($password, $hash1), 'Other-generated password validates');
ok($passphrase2->needs_rehash($hash1), 'Other-generated password does need to be regenerated');

my $hash2 = $passphrase2->recrypt_hash($hash1);
ok($passphrase2->verify_password($password, $hash2), 'Recrypted password validates');
ok(!$passphrase2->needs_rehash($hash2), 'Recrypted password doesn\'t need to be regenerated') or diag $hash2;

done_testing;
