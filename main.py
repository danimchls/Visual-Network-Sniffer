import argparse
import os
import sys
from menu import Menu

def show_available_pcaps():
    pcap_dir = "test_pcaps"
    if not os.path.isdir(pcap_dir):
        print("Diretorio test_pcaps/ nao encontrado.")
        print("Execute primeiro: python3 generate_test_pcaps.py")
        return []

    files = sorted([f for f in os.listdir(pcap_dir) if f.endswith('.pcap')])
    if not files:
        print("Nenhum arquivo PCAP encontrado em test_pcaps/")
        print("Execute: python3 generate_test_pcaps.py")
        return []

    print("Arquivos PCAP disponiveis:")
    for i, f in enumerate(files):
        size = os.path.getsize(os.path.join(pcap_dir, f))
        print(f"  [{i+1}] {f} ({size} bytes)")
    return files


def parse_args():
    parser = argparse.ArgumentParser(
        description='Visualizador de trafego de rede e simulacao de PCAP.',
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument('--live', action='store_true', help='executar captura de rede ao vivo')
    parser.add_argument('--pcap', metavar='ARQUIVO', help='arquivo PCAP ou indice de test_pcaps/ para simular')
    parser.add_argument('--pps', type=int, default=5, help='taxa de simulacao em pacotes por segundo')
    parser.add_argument('--list', action='store_true', help='listar arquivos PCAP disponiveis em test_pcaps/')
    return parser.parse_args()


def main():
    menu = Menu()
    args = parse_args()

    if args.list:
        show_available_pcaps()
        return

    if args.live:
        menu.run_live_mode()
        return

    if args.pcap:
        if args.pcap.isdigit():
            files = show_available_pcaps()
            if not files:
                return
            idx = int(args.pcap) - 1
            if 0 <= idx < len(files):
                pcap_file = os.path.join('test_pcaps', files[idx])
            else:
                print(f"Indice invalido. Use 1-{len(files)}")
                return
        else:
            pcap_file = args.pcap
    else:
        files = show_available_pcaps()
        if not files:
            return
        pcap_file = os.path.join('test_pcaps', files[0])
        print(f"\nUsando PCAP padrao: {files[0]}")
        print(f"Uso: python3 {sys.argv[0]} --pcap [arquivo.pcap|indice] --pps N\n")

    menu.run_simulation_mode(pcap_file, args.pps)
    
if __name__ == "__main__":
    main()