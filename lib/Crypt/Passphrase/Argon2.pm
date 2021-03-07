package Crypt::Passphrase::Argon2;

use strict;
use warnings;

use parent 'Crypt::Passphrase::Encoder';

use Carp 'croak';
use Crypt::Argon2;

my %encoder_for = (
	argon2i  => \&Crypt::Argon2::argon2i_pass,
	argon2d  => \&Crypt::Argon2::argon2d_pass,
	argon2id => \&Crypt::Argon2::argon2id_pass,
);

sub new {
	my ($class, %args) = @_;
	my $subtype     =  $args{subtype}     || 'argon2id';
	croak "Unknown subtype $subtype" unless $encoder_for{ $subtype };
	return bless {
		memory_cost      => $args{memory_cost}      || '256M',
		time_cost      => $args{time_cost}      ||    3,
		parallelism => $args{parallelism} ||    1,
		output_size => $args{output_size} ||   16,
		salt_size   => $args{salt_size}   ||   16,
		subtype     => $subtype,
	}, $class;
}

sub hash_password {
	my ($self, $password) = @_;
	my $salt = $self->random_bytes($self->{salt_size});
	my $encoder = $encoder_for{ $self->{subtype} };
	return $encoder->($password, $salt, $self->{time_cost}, $self->{memory_cost}, $self->{parallelism}, $self->{output_size});
}

sub needs_rehash {
	my ($self, $hash) = @_;
	return Crypt::Argon2::argon2_needs_rehash($hash, $self->{subtype}, $self->{time_cost}, $self->{memory_cost}, $self->{parallelism}, $self->{output_size}, $self->{salt_size});
}

my %matcher_for = (
	argon2i  => \&Crypt::Argon2::argon2i_verify,
	argon2d  => \&Crypt::Argon2::argon2d_verify,
	argon2id => \&Crypt::Argon2::argon2id_verify,
);

sub crypt_subtypes {
	return keys %matcher_for;
}

sub verify_password {
	my ($class, $password, $hash) = @_;
	my ($type) = $hash =~ / \A \$ ([0-9A-Za-z]+) \$ /x;
	return eval { $matcher_for{$type}->($hash, $password) };
}

#ABSTRACT: An Argon2 encoder for Crypt::Passphrase

=method new(%args)

This creates a new Argon2 encoder, it takes named parameters that are all optional. Note that some defaults are likely to change at some point in the future, as computers get progressively more powerful and cryptoanalysis gets more advanced.

=over 4

=item * memory_cost

Maximum memory (in bytes) that may be used to compute the Argon2 hash. This currently defaults to 256 megabytes, but this number may change in any future version.

=item * time_cost

Maximum amount of time it may take to compute the Argon2 hash. This currently defaults to C<3>, but this number may change in any future version.

=item * parallelism

The number of lanes (and potentially threads) used for the hash. This defaults to C<1>, but this number may change in any future version.

=item * output_size

The size of a hashed value. This defaults to 16 bytes, increasing it only makes sense if your passwords actually contain more than 128 bits of entropy.

=item * salt_size

The size of the salt. This defaults to 16 bytes, which should be more than enough for any use-case.

=item * subtype

This choses the argon2 subtype. It defaults to C<argon2id>, and unless you know what you're doing you should probably keep it at that. This may change in any future version (but is unlikely to do so unless C<argon2_id> is cryptographically broken).

=over 4

=item * 2id

This is the default. It's a hybrid of C<2i> and C<2d> that largely combines the advantages of both.

=item * 2i

This is optimized against timing attacks, but more vulnerable against other cryptographic attacks. It must not be used with a C<time_cost> lower than 3.

=item * 2d

This is optimized for resistance to GPU cracking attacks but not against timing based side-channel attacks.

=back

=back

Note: there is no wrong or right configuration, it all depends on your own particular circumstances. I recommend using the algorithm described in L<Crypt::Argon2|Crypt::Argon2/RECOMMENDED-SETTINGS> to pick the right settings for you.

=method hash_password($password)

This hashes the passwords with argon2 according to the specified settings and a random salt (and will thus return a different result each time).

=method needs_rehash($hash)

This returns true if the hash uses a different cipher or subtype, or if any of the parameters is lower that desired by the encoder.

=method crypt_types()

This class supports the following crypt types: C<argon2id>, C<argon2i> and C<argon2d>.

=method verify_password($password, $hash)

This will check if a password matches an argon2 hash.
