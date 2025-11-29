**Aviso:** não execute código desconhecido diretamente no seu PC. Sempre escaneie e revise antes, nem todo mundo na internet é legal!

Scanner estático para verificação de repositórios GitHub, que detecta padrões potencialmente perigosos em texto e em código Python.  
**Atenção:** o scanner **não executa** o código dos repositórios; só lê e analisa.

## Estrutura
- `scanner/` — código do scanner (static_repo_scanner.py)  
- `repositorios/` — repositórios clonados para análise  
- `relatorios/` — arquivos JSON gerados com os resultados

<img width="873" height="590" alt="gifsafe" src="https://github.com/user-attachments/assets/2dd44828-b0da-4cad-bc99-ef2cebccd52c" />





## Uso rápido
```bash
python scanner/static_repo_scanner.py "repositorios/meu-repo" --out relatorios/meu-repo.json
