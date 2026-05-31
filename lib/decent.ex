defmodule Decent do
  @moduledoc """
  Functions for encrypting and decrypting messages using PGP.
  """

  @doc """
  Encrypts a message using a public key.
  """
  defdelegate encrypt(message, public_key), to: Decent.Native

  @doc """
  Decrypts a message using a private key.
  """
  defdelegate decrypt(encrypted_message, private_key, private_key_passphrase \\ nil),
    to: Decent.Native

  @doc """
  Extracts and normalizes the first usable public key from a keychain (armored or binary).
  Returns `{:ok, armored_key}` or `{:error, reason}`.
  """
  defdelegate extract_key(public_key), to: Decent.Native
end
