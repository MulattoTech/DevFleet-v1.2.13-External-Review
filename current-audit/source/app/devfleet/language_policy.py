from __future__ import annotations
TEMPLATES={
'generic':('other','none','core'),'python':('python','standard-library','core'),'python-fastapi':('python','fastapi','core'),'node':('javascript','node','core'),'typescript-node':('typescript','node','core'),'typescript-next':('typescript','nextjs','core'),'go-service':('go','net-http','core'),'dotnet-service':('csharp','aspnet-core','core'),'java-spring':('java','spring-boot','core'),'rust-service':('rust','axum','core'),
'kotlin-service':('kotlin','ktor','preview'),'php-laravel':('php','laravel','preview'),'ruby-rails':('ruby','rails','preview'),'flutter':('dart','flutter','preview'),'elixir-phoenix':('elixir','phoenix','preview'),'cpp-cmake':('cpp','cmake','preview'),'shell-automation':('shell','bash','preview'),'data-r':('r','base-r','preview'),'scientific-julia':('julia','base-julia','preview'),'sql-project':('sql','migrations','preview')}
def recommend_template(language:str='',framework:str='',scale:str='',intent:str='',project_kind:str='')->str:
 l=language.lower();f=framework.lower();k=project_kind.lower()
 if 'fastapi' in f or k=='rapid-api':return 'python-fastapi'
 if 'next' in f or k in {'web-frontend','full-stack-web','browser-extension','vscode-extension'}:return 'typescript-next' if 'next' in f or k=='full-stack-web' else 'typescript-node'
 return {'python':'python','javascript':'node','typescript':'typescript-node','go':'go-service','csharp':'dotnet-service','c#':'dotnet-service','java':'java-spring','rust':'rust-service','kotlin':'kotlin-service','php':'php-laravel','ruby':'ruby-rails','dart':'flutter','elixir':'elixir-phoenix','cpp':'cpp-cmake','c++':'cpp-cmake','shell':'shell-automation','bash':'shell-automation','r':'data-r','julia':'scientific-julia','sql':'sql-project'}.get(l,'generic')
def template_metadata(name:str)->dict[str,str]:
 language,framework,maturity=TEMPLATES[name];return {'language':language,'framework':framework,'template_maturity':maturity,'language_rationale':"Selected using Dylan's DevFleet engineering preferences; this is not a scientific model benchmark."}
