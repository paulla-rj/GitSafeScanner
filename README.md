**Aviso:** não execute código desconhecido diretamente no seu PC. Sempre escaneie e revise antes — nem todo mundo na internet é confiável.

Scanner estático para triagem de repositórios Git — detecta padrões potencialmente perigosos em texto e em código Python.  
**Atenção:** o scanner **não executa** o código dos repositórios; lê e analisa apenas.

## Estrutura
- `scanner/` — código do scanner (static_repo_scanner.py)  
- `repositorios/` — repositórios clonados para análise  
- `relatorios/` — arquivos JSON gerados com os resultados

## Uso rápido
```bash
python scanner/static_repo_scanner.py "repositorios/meu-repo" --out relatorios/meu-repo.json