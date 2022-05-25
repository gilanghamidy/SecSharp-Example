using System;
using SecSharp;
using SecSharp.SGX;
using _SecSharpDomain;

namespace SimpleEnclave
{
	[Enclave]
	internal class EnclaveHashWithArray : SGXEnclaveObject
	{
		public void HMACSHA1(byte[] message, byte[] digestOut)
		{
			using (NativeMemoryScope scope = NativeMemoryScope.GetDefaultManager())
			{
				IntPtr ptr = IntPtr.Zero;
				Func<InstanceECallHeader, IntPtr> func = delegate (InstanceECallHeader header)
				{
					EnclaveHashWithArray.PS_HMACSHA1 ps_HMACSHA = new EnclaveHashWithArray.PS_HMACSHA1
					{
						message = scope.MarshalBuffer<byte>(message),
						message_count = (long)message.Length,
						digestOut = scope.MarshalBuffer<byte>(digestOut),
						digestOut_count = (long)digestOut.Length,
						header = header
					};
					ptr = scope.MarshalStruct<EnclaveHashWithArray.PS_HMACSHA1>(ps_HMACSHA);
					return ptr;
				};
				base.InvokeMethod(0, func);
			}
		}

		public void SHA1(byte[] message, byte[] digestOut)
		{
			using (NativeMemoryScope scope = NativeMemoryScope.GetDefaultManager())
			{
				IntPtr ptr = IntPtr.Zero;
				Func<InstanceECallHeader, IntPtr> func = delegate (InstanceECallHeader header)
				{
					EnclaveHashWithArray.PS_SHA1 ps_SHA = new EnclaveHashWithArray.PS_SHA1
					{
						message = scope.MarshalBuffer<byte>(message),
						message_count = (long)message.Length,
						digestOut = scope.MarshalBuffer<byte>(digestOut),
						digestOut_count = (long)digestOut.Length,
						header = header
					};
					ptr = scope.MarshalStruct<EnclaveHashWithArray.PS_SHA1>(ps_SHA);
					return ptr;
				};
				base.InvokeMethod(1, func);
			}
		}

		public EnclaveHashWithArray() : base(Default.Instance, 2)
		{
		}

		private struct PS_HMACSHA1
		{
			public InstanceECallHeader header;
			public IntPtr message;
			public long message_count;
			public IntPtr digestOut;
			public long digestOut_count;
		}

		private struct PS_SHA1
		{
			public InstanceECallHeader header;
			public IntPtr message;
			public long message_count;
			public IntPtr digestOut;
			public long digestOut_count;
		}

		private struct PS_ctor
		{
			public ConstructorECallHeader header;
		}
	}
}

namespace _SecSharpDomain
{
	internal class Default : SGXEnclaveDomain
	{
		private Default() : base("SecSharpDomain_Default.signed.so")
		{
		}

		public static Default Instance
		{
			get
			{
				return Default.singleton;
			}
		}

		private static Default singleton = new Default();
	}
}
