defmodule TPMPort do
  @moduledoc false
  use GenServer

  require Logger

  # Client calls
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def initialize_tpm(index) do
    GenServer.call(__MODULE__, {:initialize_tpm, index})
  end

  def get_public_key(index) do
    {:ok, <<_::binary-size(26), key::binary>>} = GenServer.call(__MODULE__, {:get_public_key, index})
    #{:ok, <<key::binary>>} = GenServer.call(__MODULE__, {:get_public_key, index})
    #Base.encode16(key)
    key
  end

  def sign_ecdsa(index, <<data::binary-size(32)>>) do
   {:ok, <<sign::binary>>} = GenServer.call(__MODULE__, {:sign_ecdsa, index, data})
   #Base.encode16(sign)
   sign
  end

  def get_key_index() do
    {:ok, <<index::16>>} = GenServer.call(__MODULE__, {:get_key_index})
    index
  end

  def set_key_index(index) do
    GenServer.call(__MODULE__, {:set_key_index, index})
  end

  def get_ecdh_point(index, <<data::binary-size(65)>>) do
   {:ok, <<header::binary-size(1), z_x::binary-size(32), z_y::binary-size(32)>>} = GenServer.call(__MODULE__, {:get_ecdh_point, index, data})
   z_x
  end

  # Server calls
  def init(_opts) do
    support_tpm = "./support"

    port =
      Port.open({:spawn_executable, support_tpm}, [
        :binary,
        :exit_status,
        {:packet, 4}
      ])

    {:ok, %{port: port, next_id: 1, awaiting: %{}}}
  end

  def handle_call({:initialize_tpm, index}, from, state) do
    {id, state} = send_request(state, 1, <<index::16>>)
    {:noreply, %{state | awaiting: Map.put(state.awaiting, id, from)}}
  end

  def handle_call({:get_public_key, index}, from, state) do
    {id, state} = send_request(state, 2, <<index::16>>)
    {:noreply, %{state | awaiting: Map.put(state.awaiting, id, from)}}
  end

  def handle_call({:sign_ecdsa, index, data}, from, state) do
    {id, state} = send_request(state, 3, <<index::16, data::binary>>)
    {:noreply, %{state | awaiting: Map.put(state.awaiting, id, from)}}
  end

  def handle_call({:get_key_index}, from, state) do
    {id, state} = send_request(state, 4)
    {:noreply, %{state | awaiting: Map.put(state.awaiting, id, from)}}
  end

  def handle_call({:set_key_index, index}, from, state) do
    {id, state} = send_request(state, 5, <<index::16>>)
    {:noreply, %{state | awaiting: Map.put(state.awaiting, id, from)}}
  end

  def handle_call({:get_ecdh_point, index, data}, from, state) do
    {id, state} = send_request(state, 6, <<index::16, data::binary>>)
    {:noreply, %{state | awaiting: Map.put(state.awaiting, id, from)}}
  end


  def handle_info({_port, {:data, <<req_id::32, response::binary>>} = _data}, state) do
    case state.awaiting[req_id] do
      nil ->
        {:noreply, state}

      caller ->
        case response do
          <<0::8, error_message::binary>> ->
            reason = String.to_atom(String.replace(error_message, " ", "_"))
            GenServer.reply(caller, {:error, reason})

          <<1::8>> ->
            GenServer.reply(caller, :ok)

          <<1::8, data::binary>> ->
            GenServer.reply(caller, {:ok, data})
        end

        {:noreply, %{state | awaiting: Map.delete(state.awaiting, req_id)}}
    end
  end

  def handle_info({_port, {:exit_status, status}}, _state) do
    :erlang.error({:port_exit, status})
  end

  defp send_request(state, request_type, data) do
    id = state.next_id
    Port.command(state.port, <<id::32>> <> <<request_type>> <> data)
    {id, %{state | next_id: id + 1}}
  end

 defp send_request(state, request_type) do
    id = state.next_id
    Port.command(state.port, <<id::32, request_type::8>>)
    {id, %{state | next_id: id + 1}}
  end

  end


# TPMPort.sign_ecdsa(1, hash) |> IO.inspect(limit: :infinity)

# Generate random ecdsa keypair
# :crypto.generate_key(:ecdh, :secp256r1)

# reload the code
# r TPMPort

# Verify
# :crypto.verify(:ecdsa, :sha256, :crypto.hash(:sha256,  data), sig, [ pub, :secp256r1 ])
# :crypto.verify(:ecdsa, :sha256, data, sig, [ pub, :secp256r1 ])

# UNIRIS
# <<0x54, 0xc1, 0xa8, 0x30, 0xfa, 0xfd, 0x24, 0xd5, 0xe8, 0xec, 0xe4, 0x32, 0xbd, 0x6e, 0x67, 0xd8, 0xa0, 0xe6, 0x93, 0x05, 0x3b, 0x9f, 0x0d, 0x3b, 0xed, 0x16, 0xc9, 0x10, 0xb6, 0x2c, 0xb8, 0xe9>>
