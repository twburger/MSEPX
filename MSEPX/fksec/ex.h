// ex.h: DO NOT include this file. #include fksec.h instead!



#if ! defined( AFX_EX_H__C2404C08_2791_41F1_A45E_A62EF7364105__INCLUDED_ )
#define AFX_EX_H__C2404C08_2791_41F1_A45E_A62EF7364105__INCLUDED_
#pragma once


/*! \file ex.h
\brief declares the fksec::ex exception class and the fksec::Errcode enumeration */


/*! \brief adds an intermediate catch handler's
comment to the list of catch handlers that were traversed. */
#define FKSECADDHOP(msg) AddHop( _T( __FILE__ ), __LINE__, _T( msg ) )

/*! \brief allocates and throws an exception.
NEWEX() allocates memory via operator new; it is the responsibility
of the final catch handler to catch a pointer and to delete the exception.
\param err an Errcode value designating the exception type
\param msg a string literal giving additional information; note that
_T() is supplied by this macro. */
#define NEWEX(err,msg) new ex( _T( __FILE__ ), __LINE__, (err), _T( msg ) )

/*! \brief allocates and throws an exception for a Win32 error.
NEWEX32() allocates memory via operator new; it is the responsibility
of the final catch handler to catch a pointer and to delete the exception.
\param err an Errcode value designating the exception type
\param msg a string literal giving additional information; note that
_T() is supplied by this macro.
\param err32 a Win32 error code. */
#define NEWEX32(err,msg,err32) new ex( _T( __FILE__ ), __LINE__, (err), _T( msg ), (err32) )

/*! catches an fksec::ex exception, adds a comment to the hop list, and rethrows the exception.
\param msg a string literal giving additional information; note that
_T() is supplied by this macro. */
#define RETHROWEX(msg) catch ( ex *e ) { e->AddHop( _T( __FILE__ ), __LINE__, _T( msg ) ); throw; }


namespace fksec {


/*! \brief enumerates the principal type of an exception object. */

	enum Errcode
	{
		/*! \brief no error.
		You should never see this; it is there only so I can detect 
		uninitialized error codes during development. */
		errNone,

		/*! \brief hop index out of range.
		This one is thrown if you access the hop list of an exception object 
		with an out-of-range index. */
		errBadHopIndex,

		/*! \brief too many subauthorities in SID.
		NT defines a limit on the number of subauthorities in a SID 
		(SID_MAX_SUB_AUTHORITIES); errTooManySubAuths is the reward for 
		exceeding this limit. */
		errTooManySubAuths,

		/*! \brief uninitialized or invalid SID.
		This one gets thrown every time you try to use an invalid SID, look 
		up an inexistent user, look up the user name for an inexistent SID, 
		and so on.  "Using" and invalid sid includes using it in an ace, 
		which might get used in an acl, which might be plugged into a security 
		descriptor. */
		errInvalidSid,

		/*! \brief aubauthority index out of range.
		Thrown if you try to get or set a subauthority of a sid that is not 
		present - basically, an index out-of-range error. */
		errInvalidSubAuthIndex,

		/*! \brief out of memory.
		Some of the methods for all classes need dynamically allocated memory, 
		most notably the MakeFoo() functions, where Foo is PSID, PACE, PACL, 
		PSD as appropriate.  Other uses of dynamically allocated memory 
		include buffers for name lookups in the sid class, and chunks for 
		retrieving security descriptors in the apis.cpp functions.  By now 
		you can guess what happens if such memory as is needed cannot be 
		allocated. */
		errNoMemory,

		/*! \brief buffer too small.
		This happens when you call an object's StoreFoo() method to fill a 
		buffer supplied by you, and the size you pass is not sufficient.  
		Your choices are to either ask beforehand (all objects support a 
		GetLength() method, and the acl object even has two different ones), 
		allocating a sufficiently large buffer, or to handle the exception, 
		get the required size from the exception's GetData() function, and 
		proceed from there. */
		errBufferTooSmall,

		/*! \brief ACE invalid.
		This means that you tried to set invalid inheritance flags, an 
		invalid ACE type, or the like. Invalid users or SIDs get an 
		errInvalidSid instead. */
		errInvalidAce,

		/*! \brief ACL invalid.
		Expect this exception when you feed invalid ACLs to an acl object.  
		Note that invalid users or SIDs get an errInvalidSid instead. */
		errInvalidAcl,

		/*! \brief ACE index out of range.
		The index passed to GetAce() or SetAce() (of an acl object) is out-of-range. */
		errInvalidAceIndex,

		/*! \brief cannot change privilege state.
		A privilege refused to let us set its state (to enabled or disabled). */
		errStubbornPriv,

		/*! \brief cannot query privilege state.
		A privilege's state could not be retrieved.  This should not happen; 
		if the object cannot open a token handle for TOKEN_QUERY, an errOpenToken 
		exception is thrown, and if the object did successfully open the token 
		handle, this error should not happen. */
		errQueryToken,

		/*! \brief cannot create duplicate token handle.
		If an already-opened token handle is passed to a priv object, the object 
		attempts to create a duplicate for its own use.  This error is what you 
		get if the operation fails. */
		errDupTokenHandle,

		/*! \brief failed to open process and thread tokens.
		If you leave a priv object's token handle as zero, it attempts to open 
		the current thread or process token.  If this fails, you get an 
		errOpenToken exception. */
		errOpenToken,

		/*! \brief cannot close token.
		In theory, this should not happen - assuming, that is, that I don't 
		pass invalid handles around. */
		errCloseToken,

		/*! \brief invalid or unknown privilege.
		The privilege you asked for doesn't exist. */
		errInvalidPriv,

		/*! \brief cannot grab an object's SD.
		Thrown by the functions in apis.cpp - a security descriptor could not 
		be read off an object. */
		errUnreadableSD,

		/*! \brief cannot write an object's SD.
		Thrown by the functions in apis.cpp - a security descriptor could not 
		be written to an object. */
		errUnwritableSD,

		/*! \brief uninitialized or invalid SID.
		What can I say?  I am really running out of platitudes by now ... */
		errInvalidSD,

		/*! \brief cannot find local domain's prefix SID.
		Raised by some sid lookup functions if the attempt of getting a machine's 
		domain SID (with NetUserModalsGet()) fails. Call ex::GetErrWin32() for 
		the precise error code. */
		errNoPrefixSid,

		/*! \brief invalid token handle.
		Raised by some of the token functions. */
		errInvalidHandle,

		/*! \brief AdjustToken() failed.
		Raised by some of the token functions. */
		errAdjustToken,

		/*! \brief NetUser*() failed.
		Raised by sid::Members and sid::MemberOf, if one of the NetApi32 calls
		fails. Call ex::GetErrWin32() for the precise error code */
		errNetApi32,

		/*! \brief sentinel
		You should never see this in an exception.  It serves mainly to check 
		indexes into the error string array. */
		errMaxError
	};

/*! \brief fksec throws a heap-allocated instance of ex, the exception
  class, upon encountering an error.

  The fksec classes use C++ exceptions to report errors, with a very 
  few functions reporting success or failure through normal return values 
  (these are mostly of the "IsValid()" type, which one would expect to 
  return false instead of going bang.)

  An exception object records at least one of the error codes defined in 
  the ex::Errcode enumeration, an accompanying text message, and a list 
  of source-file/line-number/error-message combinations, starting with 
  the source line that threw the exception.  Additionally, the exception 
  object may contain a Win32 error code, and a DWORD of additional data, 
  which is used to communicate minimum required buffer sizes and the like.

  <h4>Catching and handling an fksec exception</h4>

  You should expect every method of every class to throw an exception at 
  you (except where explicitly noted otherwise in a method's discussion 
  below).  That means that all your uses of fksec classes should be 
  wrapped in try … catch blocks:

\code
	try { sid.StoreSid( thatBuffer, bufferSize ); }
	catch ( ex *e )
	{
		if ( e->GetErr() == something )
		{
			// handle this exception
			e->shoo(); // and delete it
		}
		else
		{
			// clean up here
			throw;
		}
	}
\endcode

  In general you will not want to wrap every single method call into its 
  own exception handler; fksec does that internally only in order to 
  pinpoint more precisely where an error occurred or was caught and re-thrown.

  Note that you are expected to delete the fksec exceptions you catch, 
  unless you re-throw them.  Due to the possible conflict between the 
  memory allocation structures of multiple modules linked with a static 
  runtime library, the exception class provides a method to do this 
  safely - see shoo() below.

  <h4>Interpreting the contents of an ex object</h4>

  As mentioned above, the error code, accessible through GetErr() and 
  GetErrString(), is the most important part - it tells you what went 
  wrong.  If the error was caused by the failure of a Win32 API function, 
  GetErrWin32() will return a non-zero value, the result of 
  GetLastError() at the point of failure.  If the error was caused by 
  passing too small a buffer, GetData() tells you how large the buffer 
  must be; this affects mainly the StoreSid(), StoreAce(), StoreAcl(), 
  StoreSd() functions which expect a caller-supplied buffer.

  Finally, the list of source lines where the exception was thrown or 
  re-thrown on its way to you contains messages explaining what the code 
  was trying to do when the error was detected.

  Note that none of this is intended for the user's eyes; handling errors 
  is your job.  Also note carefully that NT exceptions - access violations 
  due to invalid pointers passed in, for example - are not caught or 
  handled by the code.  This is on the to-do list, though.

  \author Felix Kasza \<felixk@mvps.org\>
  \author see http://mvps.org/win32/security/fksec.html
*/
	class ex
	{
	public:
		/*! \brief describes a catch handler that re-threw the exception pointer. */
		struct Hop
		{
			/*! \brief the source file name of the re-throwing catch handler. */
			fkstr file;
			/*! \brief The source line number of the re-throwing catch handler. */
			int line;
			/*! \brief What the re-throwing catch handler has to say about all this. */
			fkstr msg;
		};

		// --- ctors/dtor ---

		/*! \brief The default ctor does precisely nothing.
		\exception none */
		ex(): errWin32( 0 ), data( 0 )									{ }
		
		/*! \brief The copy ctor initialises *this to a copy of the exception \a e.
		\param e a const reference to the exception to be copied
		\exception none */
		ex( const ex &e );
		
		/*! \brief initialises an ex object from bits and pieces supplied by you.  

		ex.h contains the NEWEX and NEWEX32 macros, which you might find 
		useful if you extend the classes and wish to stick with my exceptions.
		\param newFile name of the source file raising the exception, usually \a __FILE__
		\param newLine number of the source line raising the exception, usually \a __LINE__
		\param newErr error code represented by this exception (see Errcode)
		\param newMsg a comment which is presumably of interest to someone debugging the code
		\param newErrWin32 Win32 error code, or 0 if none
		\param newData DWORD-sized value; use depends on the exception type
		\exception none */
		ex( const TCHAR *newFile, int newLine,
			Errcode newErr, const TCHAR *newMsg,
			DWORD newErrWin32 = 0, DWORD newData = 0 );
		
		/*! \brief The dtor, well, duh. Supply your own comment here ...
		\exception none */
		virtual ~ex()										{ }
		
		/*! \brief basically executes a delete this, avoiding problems
		with multiple copies of the runtime library.
		\exception none */
		virtual void shoo();

		// --- assignment ---
		
		/*! \brief Assignment operator.
		
		I do prefer to have explicit assignment operators (or private, 
		unimplemented, ones), if only to prevent the compiler from doing 
		what it thinks best.
		\param e a const reference to the source exception
		\exception none */
		const ex &operator=( const ex &e );

		// --- accessors ---
		
		/*! \brief adds an entry to the hop list.

		AddHop() is the method that adds an entry to the exception's history. 
		(The first entry is usually made during construction of the exception 
		object.) For uses, see any of the other classes' source files.
		\param newFile name of the source file rethrowing the exception, usually \a __FILE__
		\param newLine number of the source line rethrowing the exception, usually \a __LINE__
		\param newMsg a comment which is presumably of interest to someone debugging the code
		\exception none */
		void AddHop( const TCHAR *newFile,
			int newLine, const TCHAR *newMsg );

		/*! \brief sets the object's error code.

		The operation fails silently if the error code is out-of-range.
		\param newErr the new Errcode to be set
		\exception none */
		void SetErr( Errcode newErr );
		
		/*! \brief returns the object's error code.

		\return a member of the Errcode enumeration giving the reason 
		for which the exception was thrown.
		\exception none */
		Errcode GetErr() const								{ return err; }
		
		/*! \brief retrieves the string name of the object's error code.

		Note that this is just the name of the Errcode constant, <i>not</i> 
		something you can show to a user.
		\return a const pointer to the string corresponding to the error 
		code in *this if the error code is valid, or a const pointer to
		the string "-unknown-" otherwise.
		\exception none */
		const TCHAR *GetErrString() const;

		/*! \brief sets the Win32 error code that, presumably, is the reason 
		for the exception being thrown.
		\param newErrWin32 the new Win32 error code, if applicable; else 0
		\exception none */
		void SetErrWin32( DWORD newErrWin32 )				{ errWin32 = newErrWin32; }

		/*! \brief gets the Win32 error code that, presumably, is the reason 
		for the exception being thrown.
		\return a Win32 error code.  0 means that there was no Win32 error.
		\exception none */
		DWORD GetErrWin32() const							{ return errWin32; }

		/*! \brief sets optional exception data.

		Some exceptions communicate a DWORD (say, the minimum size 
		of a buffer that was too small) to the user.  This is how.
		\param newData the new exception-type specific data value
		\exception none */
		void SetData( DWORD newData )						{ data = newData; }

		/*! \brief retrieves optional exception data.

		Some exceptions communicate a DWORD (say, the minimum size 
		of a buffer that was too small) to the user.  This method 
		retrieves that value.  If the return is 0, the value was not set.
		\return the DWORD containing additional data, or 0 if none 
		(or if 0 was explicitly set).
		\exception none */
		DWORD GetData() const								{ return data; }

		/*! \brief gets number of entries in the hop list

		The hop list has one entry for each catch handler that 
		passed the exception on (by re-throwing it), plus one 
		for the initial throw, assuming that every intermediate 
		handler bothered to add itself to the hop list.  This 
		function retrieves the number of entries in this list.
		\return the number of entries in the hop list.
		\exception none */
		size_t GetHopCount() const							{ return hops.size(); }

		/*! \brief gets a non-const reference to a hop entry.

		Hop entries are numbered 0 through GetHopCount() - 1.  
		The structure of a hop entry itself is defined in ex.h.
		\param index the zero-based index of the hop to retrieve
		\return a non-const reference to a hop entry.
		\exception errBadHopIndex */
		Hop &operator[]( size_t index );

		/*! \brief gets a const reference to a hop entry.

		Hop entries are numbered 0 through GetHopCount() - 1.  
		The structure of a hop entry itself is defined in ex.h.
		\param index the zero-based index of the hop to retrieve
		\return a const reference to a hop entry.
		\exception errBadHopIndex */
		const Hop &operator[]( size_t index ) const;

		// --- inserters ---

		//! return the string for errWin32
		fkstr GetWin32Desc() const;

		/*! \brief dumps this exception to a stream.

		An fkostream is a synonym for a std::ostream or a std::wostream, 
		depending on the Unicode settings. operator<< writes a 
		human-readable representation of the exception to such a stream, 
		useful for diagnostics.  Note that the output takes multiple 
		lines and ends with a newline.
		\param o the ostream or wostream to write to
		\param e the exception to dump
		\return the fkostream reference that was passed in, as usual
		for inserters.
		\exception unpredictable depends on the iostreams library. */
		friend fkostream &operator<<( fkostream &o, const ex& e );

	private:
		/*! \brief the list of catch handlers that were traversed */
		typedef std::vector<Hop> HopList;

		/*! \brief the list of catch handlers having seen the exception

		As the exception bubbles its way up the call stack, catch
		handlers add their comments to this list.
		\sa #AddHop */
		fksec::ex::HopList hops;

		/*! \brief the error code. Meanings are listed in the documentation
		for the fksec::Errcode enumeration. */
		fksec::Errcode err;

		/*! \brief the Win32 error code that caused the exception, if any; else 0. */
		DWORD errWin32;

		/*! \brief additional data, if any; else 0. */
		DWORD data;

		/*! \brief name strings for the Errcode enumeration values. */
		static const TCHAR *errStrings[];

		/*! \brief the count of string pointers in the errStrings[] array. */
		static const int numErrStrings;
	};

	/*! \brief dumps this exception to a stream.

	An fkostream is a synonym for a std::ostream or a std::wostream, 
	depending on the Unicode settings. operator<< writes a 
	human-readable representation of the exception to such a stream, 
	useful for diagnostics.  Note that the output takes multiple 
	lines and ends with a newline.
	\param o the ostream or wostream to write to
	\param e the exception to dump
	\return the fkostream reference that was passed in, as usual
	for inserters.
	\exception unpredictable depends on the iostreams library. */
	fkostream &operator<<( fkostream &o, const ex& e );

} // namespace fksec

#endif // ! defined( AFX_SID_H__C2404C08_2791_41F1_A45E_A62EF7364105__INCLUDED_ )
