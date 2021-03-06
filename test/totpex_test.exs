defmodule TotpexTest do
  use ExUnit.Case

  # RFCs
  # ====
  #  - HOTP, 4226: https://tools.ietf.org/html/rfc4226
  #  - TOTP, 6238: https://tools.ietf.org/html/rfc6238

  setup do
    %{
      test_vectors: [
        # { unix_timestamp, date_string, expected_token, hash_alg }
        {59, "1970-01-01 00:00:59", "082", :sha},
        {59, "1970-01-01 00:00:59", "246", :sha256},
        {59, "1970-01-01 00:00:59", "936", :sha512},
        {59, "1970-01-01 00:00:59", "287082", :sha},
        {59, "1970-01-01 00:00:59", "119246", :sha256},
        {59, "1970-01-01 00:00:59", "693936", :sha512},
        {59, "1970-01-01 00:00:59", "94287082", :sha},
        {59, "1970-01-01 00:00:59", "46119246", :sha256},
        {59, "1970-01-01 00:00:59", "90693936", :sha512},

        {1111111109, "2005-03-18 01:58:29", "804", :sha},
        {1111111109, "2005-03-18 01:58:29", "774", :sha256},
        {1111111109, "2005-03-18 01:58:29", "201", :sha512},
        {1111111109, "2005-03-18 01:58:29", "081804", :sha},
        {1111111109, "2005-03-18 01:58:29", "084774", :sha256},
        {1111111109, "2005-03-18 01:58:29", "091201", :sha512},
        {1111111109, "2005-03-18 01:58:29", "07081804", :sha},
        {1111111109, "2005-03-18 01:58:29", "68084774", :sha256},
        {1111111109, "2005-03-18 01:58:29", "25091201", :sha512},

        {1111111111, "2005-03-18 01:58:31", "471", :sha},
        {1111111111, "2005-03-18 01:58:31", "674", :sha256},
        {1111111111, "2005-03-18 01:58:31", "326", :sha512},
        {1111111111, "2005-03-18 01:58:31", "050471", :sha},
        {1111111111, "2005-03-18 01:58:31", "062674", :sha256},
        {1111111111, "2005-03-18 01:58:31", "943326", :sha512},
        {1111111111, "2005-03-18 01:58:31", "14050471", :sha},
        {1111111111, "2005-03-18 01:58:31", "67062674", :sha256},
        {1111111111, "2005-03-18 01:58:31", "99943326", :sha512},

        {1234567890, "2009-02-13 23:31:30", "924", :sha},
        {1234567890, "2009-02-13 23:31:30", "424", :sha256},
        {1234567890, "2009-02-13 23:31:30", "116", :sha512},
        {1234567890, "2009-02-13 23:31:30", "005924", :sha},
        {1234567890, "2009-02-13 23:31:30", "819424", :sha256},
        {1234567890, "2009-02-13 23:31:30", "441116", :sha512},
        {1234567890, "2009-02-13 23:31:30", "89005924", :sha},
        {1234567890, "2009-02-13 23:31:30", "91819424", :sha256},
        {1234567890, "2009-02-13 23:31:30", "93441116", :sha512},

        {2000000000, "2033-05-18 03:33:20", "037", :sha},
        {2000000000, "2033-05-18 03:33:20", "825", :sha256},
        {2000000000, "2033-05-18 03:33:20", "901", :sha512},
        {2000000000, "2033-05-18 03:33:20", "279037", :sha},
        {2000000000, "2033-05-18 03:33:20", "698825", :sha256},
        {2000000000, "2033-05-18 03:33:20", "618901", :sha512},
        {2000000000, "2033-05-18 03:33:20", "69279037", :sha},
        {2000000000, "2033-05-18 03:33:20", "90698825", :sha256},
        {2000000000, "2033-05-18 03:33:20", "38618901", :sha512},

        {20000000000, "2603-10-11 11:33:20", "130", :sha},
        {20000000000, "2603-10-11 11:33:20", "706", :sha256},
        {20000000000, "2603-10-11 11:33:20", "826", :sha512},
        {20000000000, "2603-10-11 11:33:20", "353130", :sha},
        {20000000000, "2603-10-11 11:33:20", "737706", :sha256},
        {20000000000, "2603-10-11 11:33:20", "863826", :sha512},
        {20000000000, "2603-10-11 11:33:20", "65353130", :sha},
        {20000000000, "2603-10-11 11:33:20", "77737706", :sha256},
        {20000000000, "2603-10-11 11:33:20", "47863826", :sha512},
      ]
    }
  end

  test "Rfc test vectors test", %{test_vectors: test_vectors} do
    test_vectors |> Enum.map(fn {ts, _, token, hash} ->
      secret = generate_secret(hash_length(hash))
      val = Totpex.generate_totp(secret, ts, length: String.length(token), hash: hash)

      assert(val == token, "{#{ts}, #{hash}} expected #{token} was #{val}")
    end)
  end

  defp hash_length(:sha), do: 20
  defp hash_length(:sha256), do: 32
  defp hash_length(:sha512), do: 64

  defp generate_secret(length) do
    1..length |> Enum.map(& rem(&1, 10)+0x30) |> to_string()
  end
end
