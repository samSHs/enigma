#!/usr/bin/env python3
"""Simulador educativo da Enigma I. Python 3.10+, sem dependencias.

Referencias para as ligacoes e o mecanismo:
https://www.cryptomuseum.com/crypto/enigma/wiring.htm
https://www.cryptomuseum.com/crypto/enigma/working.htm

A interface usa letras A-Z nas janelas e nos aneis (A=01, ..., Z=26).
Nao implementa os procedimentos militares de distribuicao de chaves.
Nao use esta cifra historica para proteger dados reais.
"""

import argparse
import sys
import unicodedata

ALFABETO = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ROTORES = {
    "I":   ("EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q"),
    "II":  ("AJDKSIRUXBLHWTMCQGZNPYFVOE", "E"),
    "III": ("BDFHJLCPRTXVZNYEIWGAKMUSQO", "V"),
    "IV":  ("ESOVPZJAYQUIRHXLNFTGKDCMWB", "J"),
    "V":   ("VZBRGITYUPSDNHLXAWMJQOFECK", "Z"),
}
REFLETORES = {
    "B": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
    "C": "FVPJIAOYEDRZXWGCTKUQSBNMHL",
}


def normalizar(texto: str) -> str:
    """Conveniencia moderna: retira acentos e conserva somente A-Z."""
    texto = unicodedata.normalize("NFD", texto.upper())
    return "".join(c for c in texto if c in ALFABETO)


def validar_tripla(valor: str, campo: str) -> str:
    valor = valor.strip().upper()
    if len(valor) != 3 or any(c not in ALFABETO for c in valor):
        raise ValueError(f"{campo}: use exatamente 3 letras de A a Z.")
    return valor


class Rotor:
    def __init__(self, nome: str, anel: str, posicao: str):
        ligacao, entalhe = ROTORES[nome]
        self.ida = [ALFABETO.index(c) for c in ligacao]
        self.volta = [self.ida.index(i) for i in range(26)]
        self.entalhe = ALFABETO.index(entalhe)
        self.anel = ALFABETO.index(anel)
        self.posicao = ALFABETO.index(posicao)

    def no_entalhe(self) -> bool:
        # O entalhe acompanha o anel de letras, nao o nucleo eletrico.
        return self.posicao == self.entalhe

    def avancar(self) -> None:
        self.posicao = (self.posicao + 1) % 26

    def passar(self, sinal: int, inverso: bool = False) -> int:
        deslocamento = self.posicao - self.anel
        mapa = self.volta if inverso else self.ida
        entrada = (sinal + deslocamento) % 26
        return (mapa[entrada] - deslocamento) % 26


class Enigma:
    def __init__(
        self,
        rotores: tuple[str, str, str] = ("I", "II", "III"),
        posicao: str = "AAA",
        aneis: str = "AAA",
        refletor: str = "B",
        plugs: str = "",
    ):
        """Rotores, posicoes e aneis sempre da esquerda para a direita."""
        self.nomes = tuple(nome.upper() for nome in rotores)
        if len(self.nomes) != 3 or len(set(self.nomes)) != 3:
            raise ValueError("Escolha tres rotores diferentes.")
        if any(nome not in ROTORES for nome in self.nomes):
            raise ValueError("Rotores disponiveis: I, II, III, IV e V.")
        self.inicial = validar_tripla(posicao, "Posicao")
        self.aneis = validar_tripla(aneis, "Aneis")
        self.nome_refletor = refletor.upper()
        if self.nome_refletor not in REFLETORES:
            raise ValueError("O refletor deve ser B ou C.")
        self.refletor = [
            ALFABETO.index(c) for c in REFLETORES[self.nome_refletor]
        ]
        self.plugs = " ".join(plugs.upper().split())
        self.painel = self._criar_painel(self.plugs)
        self.rotores = [
            Rotor(nome, anel, pos)
            for nome, anel, pos in zip(self.nomes, self.aneis, self.inicial)
        ]

    @staticmethod
    def _criar_painel(plugs: str) -> list[int]:
        pares = plugs.split()
        if len(pares) > 10:
            raise ValueError("Esta versao permite ate 10 pares de plugs.")
        painel = list(range(26))
        usadas: set[str] = set()
        for par in pares:
            if (len(par) != 2 or any(c not in ALFABETO for c in par)
                    or par[0] == par[1]):
                raise ValueError(f"Par invalido: {par!r}. Exemplo: AB CD EF.")
            if usadas.intersection(par):
                raise ValueError(f"Letra repetida no painel: {par!r}.")
            a, b = (ALFABETO.index(c) for c in par)
            painel[a], painel[b] = b, a
            usadas.update(par)
        return painel

    @property
    def posicao(self) -> str:
        return "".join(ALFABETO[r.posicao] for r in self.rotores)

    def reposicionar(self, posicao: str | None = None) -> None:
        alvo = self.inicial if posicao is None else posicao
        alvo = validar_tripla(alvo, "Posicao")
        for rotor, letra in zip(self.rotores, alvo):
            rotor.posicao = ALFABETO.index(letra)

    def _avancar(self) -> None:
        esquerda, meio, direita = self.rotores
        # Verificar ANTES de mover: preserva o passo duplo do rotor central.
        meio_no_entalhe = meio.no_entalhe()
        direita_no_entalhe = direita.no_entalhe()
        if meio_no_entalhe:
            esquerda.avancar()
        if meio_no_entalhe or direita_no_entalhe:
            meio.avancar()
        direita.avancar()

    def processar(self, texto: str) -> str:
        """Cifra/decifra e conserva a posicao final para a proxima chamada."""
        resultado = []
        for letra in normalizar(texto):
            self._avancar()  # A rotacao acontece antes da passagem do sinal.
            sinal = self.painel[ALFABETO.index(letra)]
            for rotor in reversed(self.rotores):
                sinal = rotor.passar(sinal)
            sinal = self.refletor[sinal]
            for rotor in self.rotores:
                sinal = rotor.passar(sinal, inverso=True)
            resultado.append(ALFABETO[self.painel[sinal]])
        return "".join(resultado)


def formatar(texto: str, grupos: bool) -> str:
    if grupos:
        return " ".join(texto[i:i + 5] for i in range(0, len(texto), 5))
    return texto


def interativo(maquina: Enigma, grupos: bool) -> None:
    print("=== ENIGMA I | Simulador educativo ===")
    print("Acentos sao removidos; espacos, numeros e pontuacao sao ignorados.")
    print("As posicoes continuam entre mensagens. Use /reset para recomecar.")
    print("Comandos: /reset | /pos ABC | /status | /ajuda | /sair")
    while True:
        try:
            texto = input(f"[{maquina.posicao}] > ")
        except (EOFError, KeyboardInterrupt):
            print("\nEncerrado.")
            return
        if not texto.strip():
            continue
        if texto.lstrip().startswith("/"):
            partes = texto.strip().split()
            comando, args = partes[0].lower(), partes[1:]
            if comando == "/sair" and not args:
                return
            if comando == "/reset" and not args:
                maquina.reposicionar()
            elif comando == "/pos" and len(args) == 1:
                try:
                    maquina.reposicionar(args[0])
                except ValueError as erro:
                    print(f"Erro: {erro}")
            elif comando == "/status" and not args:
                print(f"Rotores (E->D): {' '.join(maquina.nomes)}")
                print(f"Posicao: {maquina.posicao} | Inicial: {maquina.inicial}")
                print(f"Aneis: {maquina.aneis} | Refletor: {maquina.nome_refletor}")
                print(f"Plugs: {maquina.plugs or '(nenhum)'}")
            elif comando == "/ajuda" and not args:
                print("/reset: volta a posicao inicial; /pos ABC: muda as janelas.")
                print("/status: configuracao; /sair: encerra.")
                print("Para decifrar, restaure a configuracao e a posicao de inicio.")
            else:
                print("Comando invalido. Digite /ajuda.")
            continue
        resultado = maquina.processar(texto)
        print(formatar(resultado, grupos) or "(Nenhuma letra de A a Z.)")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Enigma I: cifra e decifra com a mesma configuracao.",
        epilog="Sem --texto: terminal interativo ou leitura da entrada padrao.",
    )
    parser.add_argument("--rotores", nargs=3, type=str.upper, choices=ROTORES,
                        default=("I", "II", "III"), metavar="ROTOR",
                        help="tres rotores, da esquerda para a direita")
    parser.add_argument("--posicao", default="AAA", help="janelas iniciais: AAA")
    parser.add_argument("--aneis", default="AAA", help="aneis: AAA (A=01, Z=26)")
    parser.add_argument("--refletor", type=str.upper, choices=REFLETORES,
                        default="B", help="refletor B ou C; padrao: B")
    parser.add_argument("--plugs", default="", help='pares como "AB CD EF"')
    parser.add_argument("--grupos", action="store_true", help="grupos de 5 letras")
    modo = parser.add_mutually_exclusive_group()
    modo.add_argument("-t", "--texto", help="processa uma mensagem e encerra")
    modo.add_argument("-i", "--interativo", action="store_true",
                      help="forca o modo interativo")
    args = parser.parse_args()
    try:
        maquina = Enigma(tuple(args.rotores), args.posicao, args.aneis,
                         args.refletor, args.plugs)
    except ValueError as erro:
        parser.error(str(erro))
    if args.texto is not None:
        print(formatar(maquina.processar(args.texto), args.grupos))
    elif args.interativo or sys.stdin.isatty():
        interativo(maquina, args.grupos)
    else:
        print(formatar(maquina.processar(sys.stdin.read()), args.grupos))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
