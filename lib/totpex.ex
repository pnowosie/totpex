defmodule Totpex do
  @moduledoc """
  Generate a Time-Based One-Time Password used from 2 factor authentication.
  Official specification: https://tools.ietf.org/html/rfc6238
  """

  defp generate_hmac(key, timesteps, hash_alg) do
    # Generate the moving mactor
    moving_factor = timesteps
                    |> Integer.to_string(16)
                    |> String.pad_leading(16, "0")
                    |> String.upcase
                    |> Base.decode16!

    # Generate SHA-1
    :crypto.hmac(hash_alg, key, moving_factor)
  end

  defp hmac_dynamic_truncation(hmac) do
    # Get the offset from last  4-bits
    size_but_last = byte_size(hmac)-1
    <<_::size(size_but_last)-binary, _::4, offset::4>> = hmac

    # Get the 4-bytes starting from the offset
    <<_::size(offset)-binary, p::4-binary, _::binary>> = hmac

    # Return the last 31-bits
    <<_::1, truncation::31>> = p

    truncation
  end

  defp generate_hotp(truncated_hmac, length) do
    modulus = :math.pow(10, length) |> round

    truncated_hmac
    |> rem(modulus)
    |> Integer.to_string
    |> String.pad_leading(length, "0")
  end

  defp calculate_timesteps(unixtime, inittime, period) do
    (unixtime - inittime) |> Integer.floor_div(period)
  end

  @doc """
  Generate Time-Based One-Time Password.
  The default period used to calculate the moving factor is 30s
  """
  def generate_totp(key, unixtime, keywords \\ []) do
    hash_alg = Keyword.get(keywords, :hash, :sha)
    length = Keyword.get(keywords, :length, 6)
    timesteps = calculate_timesteps(unixtime, 0, 30)

    key
    |> generate_hmac(timesteps, hash_alg)
    |> hmac_dynamic_truncation
    |> generate_hotp(length)
  end
end
