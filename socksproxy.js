// http://www.ietf.org/rfc/rfc1928.txt

// Tested with: curl http://www.google.se/ --socks5 1080 --proxy-user foo:bar

var States = {
  CONNECTED:0,
  VERIFYING:1,
  READY:2,
  PROXY: 3
};
var AuthMethods = {
  NOAUTH:0,
  GSSAPI:1,
  USERPASS:2
}
var CommandType ={
  TCPConnect:1,
  TCPBind:2,
  UDPBind:3
}
var AddressTypes = {
  IPv4: 0x01,
  DomainName: 0x03,
  IPv6: 0x04,

  read: function(buffer,offset){
    if(buffer[offset] == AddressTypes.IPv4){
      return buffer[offset+1] + "." +
             buffer[offset+2] + "." +
             buffer[offset+3] + "." +
             buffer[offset+4];
    }else if(buffer[offset] == AddressTypes.DomainName){
      return buffer.toString('utf8',
        buffer[offset+2],
        buffer[offset+2+buffer[offset+1]]
        );
    }else if(buffer[offset] == AddressTypes.IPv6){
      return buffer.slice(buffer[offset+1], buffer[offset+1+16])
    }
  },

  sizeOf: function(buffer,offset){
    if(buffer[offset] == AddressTypes.IPv4){
        return 4;
      }else if(buffer[offset] == AddressTypes.DomainName){
        return buffer[offset+1];
      }else if(buffer[offset] == AddressTypes.IPv6){
        return 16;
      }
   }
}
var net = require('net');
var clients = [];
function accept(socket){
  clients.push(socket);
  socket.pstate = States.CONNECTED;

  socket.on('end',function(){
    clients.splice(clients.indexOf(socket),1);
  });
  var handshake = function(chunk){
    socket.removeListener('data',handshake);
    //SOCKS Version
    if(chunk[0]!= 5){
      socket.end();
    }
    n= chunk[1]; // Number of auth methods

    socket.methods=[];
    for(i=0;i<n;i++){
      socket.methods.push(chunk[1+i]);
    }
    //console.log('AuthMethods: '+socket.methods);

    var resp = new Buffer(2);
    resp[0] = 0x05;
    if(socket.methods.indexOf(AuthMethods.USERPASS)){
      socket.authUSERPASS = authUSERPASS.bind(socket);
      socket.on('data',socket.authUSERPASS);
      socket.pstate=States.VERIFYING;
      resp[1] = AuthMethods.USERPASS;
      socket.write(resp);
    }else{
      resp[1]=0xFF
      socket.end(resp);
    }
  }
  socket.on('data',handshake);
}

function authUSERPASS(chunk){

 this.removeListener('data',this.authUSERPASS);
 resp = new Buffer(2);
 resp[0]=1; //Version
 resp[1]=0xff;
 if(chunk[0] != 1){
   this.end(resp); // Wrong auth version, closing connection.
   return;
 }
 nameLength= chunk[1];
 username= chunk.toString('utf8',2,2+nameLength);

 passLength=chunk[2+nameLength];
 password= chunk.toString('utf8',3+nameLength,3+nameLength+passLength);
 //console.log('Authorizing: '+username);
 if(authorize(username,password)){
   this.pstate=States.READY;
   this.handleRequest=handleRequest.bind(this);
   this.on('data',this.handleRequest);
   resp[1]=0x00;
   this.write(resp);
   //console.log('Accepted');
 }else{
   this.end(resp);
   //console.log('Denied');
 }

}
function authorize(username,password){
 return true;
}

function handleRequest(chunk){
  this.removeListener('data',this.handleRequest);

  if(chunk[0] != 5){
    chunk[1] = 0x01;
    this.end(chunk); // Wrong version.
    return;
  }
  offset = 3;
  var address = AddressTypes.read(chunk,offset);
  offset+=AddressTypes.sizeOf(chunk,offset) +1;
  var port = chunk.readUInt16(offset,'big');
  //console.log('Request', chunk[1], " to: "+ address+":"+port);

  if(chunk[1]== CommandType.TCPConnect){
    this.request = chunk;
    this.proxy =  net.createConnection(port,address,initProxy.bind(this));
  }else{
    this.end(chunk);
  }
}

function initProxy(){
  //console.log('Proxy Connected');
  var resp = new Buffer(this.request.length);
  this.request.copy(resp);
  resp[1]=0x00;
  this.write(resp);
  this.proxy.on('data', function(data){
    this.write(data);
  }.bind(this));
  this.on('data',function(data){
    this.proxy.write(data);
  }.bind(this));
}

function dump(chunk){
  console.log('dumping:');
  console.log(chunk.toString('utf8'));
}


var server= net.createServer(accept);
server.listen(1080);
