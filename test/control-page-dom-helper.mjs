// Minimal deterministic DOM fixture for controller tests, not a rendering engine.
// This deliberately does not claim browser, layout, focus order or accessibility QA.
const voids = new Set(['meta','link','input','br','hr','img','source','wbr']);
function matches(node, selector) {
  let checked = false; if (selector.endsWith(':checked')) { checked=true;selector=selector.slice(0,-8); }
  if (checked && !node.checked) return false;
  if(selector.startsWith('#'))return node.id===selector.slice(1);
  if(selector.startsWith('.'))return node.className.split(/\s+/).includes(selector.slice(1));
  const attr=selector.match(/^\[([^=\]]+)(?:=["']?([^"'\]]+)["']?)?\]$/);if(attr)return node.hasAttribute(attr[1])&&(attr[2]===undefined||node.getAttribute(attr[1])===attr[2]);
  return node.tagName===selector.toLowerCase();
}
export class FixtureElement {
 constructor(tag,document){this.tagName=tag.toLowerCase();this.ownerDocument=document;this.children=[];this.parentElement=null;this.attributes={};this.handlers=new Map();this._text='';this._value=undefined;this.hidden=false;this.checked=false;this.disabled=false;this.required=false;this.readOnly=false;this.open=false;this.dataset=new Proxy({}, {set:(object,key,value)=>{object[key]=value;this.attributes['data-'+key.replace(/[A-Z]/g,c=>'-'+c.toLowerCase())]=String(value);return true;}});this.classList={toggle:(name,force)=>{const values=new Set(this.className.split(/\s+/).filter(Boolean));const yes=force??!values.has(name);yes?values.add(name):values.delete(name);this.className=[...values].join(' ');return yes;}};}
 set id(value){this.attributes.id=value;}get id(){return this.attributes.id??'';}
 set className(value){this.attributes.class=value;}get className(){return this.attributes.class??'';}
 set name(value){this.attributes.name=value;}get name(){return this.attributes.name??'';}
 set type(value){this.attributes.type=value;}get type(){return this.attributes.type??'';}
 set value(value){this._value=String(value);if(this.type==='checkbox'||this.tagName==='option')this.attributes.value=String(value);}get value(){if(this.tagName==='select'){const options=this.options;return options.some(o=>o.value===this._value)?this._value:options.find(o=>o.hasAttribute('selected'))?.value??options[0]?.value??'';}return this._value??this.attributes.value??(this.tagName==='option'||this.tagName==='textarea'?this.textContent:'');}
 get options(){return this.querySelectorAll('option');}get selectedOptions(){return this.options.filter(o=>o.value===this.value);}get firstElementChild(){return this.children[0]??null;}
 set textContent(value){this._text=String(value??'');for(const child of this.children)child.parentElement=null;this.children=[];}get textContent(){return this._text+this.children.map(c=>c.textContent).join('');}
 setAttribute(name,value){this.attributes[name]=String(value);if(['hidden','disabled','required','checked','readonly'].includes(name))this[name==='readonly'?'readOnly':name]=true;if(name.startsWith('data-'))this.dataset[name.slice(5).replace(/-([a-z])/g,(_,c)=>c.toUpperCase())]=String(value);}
 getAttribute(name){return this.attributes[name]??null;}hasAttribute(name){return Object.hasOwn(this.attributes,name);}removeAttribute(name){delete this.attributes[name];}
 append(...nodes){for(let node of nodes){if(typeof node==='string'){const text=new FixtureElement('#text',this.ownerDocument);text.textContent=node;node=text;}node.parentElement=this;this.children.push(node);}}
 replaceChildren(...nodes){for(const child of this.children)child.parentElement=null;this.children=[];this._text='';this.append(...nodes);}remove(){if(this.parentElement){this.parentElement.children=this.parentElement.children.filter(node=>node!==this);this.parentElement=null;}}
 querySelectorAll(selector){const parts=selector.trim().split(/\s+/),all=[];const walk=node=>{for(const child of node.children){if(matches(child,parts.at(-1))){let current=child.parentElement,index=parts.length-2;while(current&&index>=0){if(matches(current,parts[index]))index--;current=current.parentElement;}if(index<0)all.push(child);}walk(child);}};walk(this);return all;}
 querySelector(selector){return this.querySelectorAll(selector)[0]??null;}
 addEventListener(type,handler){if(!this.handlers.has(type))this.handlers.set(type,[]);this.handlers.get(type).push(handler);}
 dispatch(type,values={}){const event={type,target:this,defaultPrevented:false,preventDefault(){this.defaultPrevented=true;},...values};let node=this;while(node){for(const handler of node.handlers.get(type)??[])handler(event);node=node.parentElement;}return event;}
 focus(){this.ownerDocument.activeElement=this;}scrollIntoView(){}
 reset(){for(const node of [...this.querySelectorAll('input'),...this.querySelectorAll('select'),...this.querySelectorAll('textarea')]){node._value=node.attributes.value;node.checked=node.hasAttribute('checked');}}
}
export function fixtureDocument(html){
 const document={visibilityState:'visible',activeElement:null};const root=new FixtureElement('document',document);document.createElement=tag=>new FixtureElement(tag,document);document.querySelectorAll=selector=>root.querySelectorAll(selector);document.getElementById=id=>root.querySelector('#'+id);document.root=root;
 const stack=[root];for(const token of html.match(/<!--[\s\S]*?-->|<![^>]*>|<[^>]+>|[^<]+/g)??[]){if(token.startsWith('<!'))continue;if(token.startsWith('</')){stack.pop();continue;}if(token.startsWith('<')){const [,tag,raw]=token.match(/^<([\w-]+)([\s\S]*?)\/?\s*>$/)??[];if(!tag)continue;const node=new FixtureElement(tag,document);for(const attr of raw.matchAll(/([\w:-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s]+)))?/g))node.setAttribute(attr[1],attr[2]??attr[3]??attr[4]??'');stack.at(-1).append(node);if(!voids.has(tag.toLowerCase()))stack.push(node);}else{const text=new FixtureElement('#text',document);text.textContent=token;stack.at(-1).append(text);}}
 document.body=root.querySelector('body');return document;
}
export async function settle(){for(let i=0;i<8;i++)await new Promise(resolve=>setImmediate(resolve));}
