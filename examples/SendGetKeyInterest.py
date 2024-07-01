import sys
from Cryptodome.PublicKey import ECC
from ndn import appv2, types, encoding as enc
from ndn.security import Certificate, Key

app = appv2.NDNApp()
signer = app.default_keychain().get_signer({})


async def main(key_locator):
    try:
        name = enc.Name.from_str(key_locator)
        print(f'Sending Interest {enc.Name.to_str(name)}, {enc.InterestParam(must_be_fresh=True, lifetime=6000)}')
        data_name, content, pkt_context = await app.express(
            name, validator=appv2.pass_all, signer=signer,
            must_be_fresh=True, can_be_prefix=False, lifetime=6000)

        print(f'Received Data Name: {enc.Name.to_str(data_name)}')
        print(pkt_context['meta_info'])
        print(bytes(content) if content else None)
        k = ECC.import_key(content)
        print(k)
        print(k.has_private())

    except types.InterestNack as e:
        print(f'Nacked with reason={e.reason}')
    except types.InterestTimeout:
        print(f'Timeout')
    except types.InterestCanceled:
        print(f'Canceled')
    except types.ValidationFailure:
        print(f'Data failed to validate')
    finally:
        app.shutdown()


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise ValueError('Please provide the key locator to get')
    kl = sys.argv[1]
    app.run_forever(after_start=main(kl))
