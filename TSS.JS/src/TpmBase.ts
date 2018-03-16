﻿/* 
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */


import { TPM_CC, TPM_RC, TPM_RH, TPM_ST, TPM_HANDLE } from "./TpmTypes.js";
import { TpmError, TpmDevice, TpmTcpDevice, TpmTbsDevice, TpmLinuxDevice } from "./TpmDevice.js";
import { TpmBuffer, TpmMarshaller } from "./TpmMarshaller.js";
import * as tss from "./Tss.js";
import { Tpm } from "./Tpm.js";

export { TpmError };

export class TpmBase
{
    //
    // TPM object state
    //
    private device: TpmDevice;

    /**
	 *  Response code returned by the last executed command
     */
    private _lastResponseCode: TPM_RC = TPM_RC.NOT_USED;

    /**
	 *  Error object (may be null) generated during the last TPM command execution
     */
    private _lastError: TpmError = null;

    //
    // Per-command state
    //

    /**
	 *  TPM sessions associated with the next command.
     */
    private sessions: tss.Session[] = null;

    /**
	 *  Suppresses exceptions in response to the next command failure, when exceptions are enabled
     */
	private exceptionsEnabled: boolean = false;

    /**
	 *  Suppresses exceptions in response to the next command failure, when exceptions are enabled
     */
	private errorsAllowed: boolean = true;

    //
    // Scratch members
    //
    private cmdTag: TPM_ST;


    private static isCommMediumError(code: TPM_RC): boolean
    {
        // TBS or TPMSim protocol error
        return (code & 0xFFFF0000) == 0x80280000;
    }

    private static cleanResponseCode(rawResponse: TPM_RC): TPM_RC
    {
        if (this.isCommMediumError(rawResponse))
            return rawResponse;

        let mask: number = (rawResponse & TPM_RC.RC_FMT1) != 0
                         ? TPM_RC.RC_FMT1 | 0x3F : TPM_RC.RC_WARN | TPM_RC.RC_VER1 | 0x7F;
        return rawResponse & mask;
    }


    constructor(useSimulator: boolean = false,
                host: string = '127.0.0.1', port: number = 2321)
    {
        this.device = useSimulator ? new TpmTcpDevice(host, port)
                    : process.platform == 'win32' ? new TpmTbsDevice()
                                                  : new TpmLinuxDevice();
    }
    
    public connect(continuation: () => void)
    {
        this.device.connect(continuation);
    }

    public close(): void
    {
        this.device.close();
        this.device = null;
    }

    get lastResponseCode(): TPM_RC
    {
        return this._lastResponseCode;
    }

    get lastError(): TpmError { return this._lastError; }

	/**
	 * For the next TPM command invocation, errors will not cause an exception to be thrown
	 * (use _lastCommandSucceeded or _getLastResponseCode() to check for an error)
	 * 
	 * @return The same object (to allow modifier chaining)
	 */
	public allowErrors(): Tpm
	{
		this.errorsAllowed = true;
		return <Tpm><Object>this;
	}
	
	/**
	 * When exceptions are enabled, errors reported by the TPM or occurred in the TSS (e.g. during 
     * an attempt to communicate with the TPM) will result in throwing an exception of TpmError type.
	 * It will still be possible to use _lastCommandSucceeded(), _getLastResponseCode() methods and
     * lastError property to check for an error after the exception is intercepted.
     * Note that in contrast to allowErrors() this method affects all subsequent commands. 
	 */
    public enableExceptions(enable: boolean = true): void
	{
		this.exceptionsEnabled = enable;
        this.errorsAllowed = !enable;
	}

	/**
	 * Specifies a single session handle to use with the next command 
	 * 
	 * @param hh List of up to 3 session handles 
	 * @return This TPM object
	 */
    public withSession(sess: tss.Session): Tpm
	{
		this.sessions = new Array<tss.Session>(sess);
		return <Tpm><Object>this;
	}

	/**
	 * Specifies the session handles to use with the next command 
	 * 
	 * @param hh List of up to 3 session handles 
	 * @return This TPM object
	 */
    public withSessions(...sess: tss.Session[]): Tpm
	{
		this.sessions = new Array<tss.Session>(...sess);
		return <Tpm><Object>this;
	}

    protected prepareCmdBuf(
        cmdCode: TPM_CC,
        handles: TPM_HANDLE[]
    ): TpmBuffer
    {
        let cmdBuf = new TpmBuffer(4096);

        this.cmdTag = this.sessions != null && this.sessions.length > 0 ? TPM_ST.SESSIONS : TPM_ST.NO_SESSIONS;
        cmdBuf.toTpm(this.cmdTag, 2);
        cmdBuf.toTpm(0, 4); // to be filled in later
        cmdBuf.toTpm(cmdCode, 4);

        if (handles != null)
        {
            for (let h of handles)
            {
                if (h == null)
                    cmdBuf.toTpm(TPM_RH.NULL, 4);
                else
                    h.toTpm(cmdBuf);
            }
        }

        if (this.cmdTag == TPM_ST.SESSIONS)
        {
            // We do not know the size of the authorization area yet.
            // Remember the place to marshal it, ...
            let authSizePos = cmdBuf.curPos;
            // ... and marshal a placeholder 0 value for now.
            cmdBuf.toTpm(0, 4);

            for (let sess of this.sessions)
            {
                sess.SessIn.toTpm(cmdBuf);
            }
            cmdBuf.buffer.writeUInt32BE(cmdBuf.curPos - authSizePos - 4, authSizePos);
        }
        this.sessions = null;
        return cmdBuf;
    }

    private ResponseHandler: (resp: TpmBuffer) => void;
    private CmdBuf: TpmBuffer;

    private InterimResponseHandler (err: TpmError, respBuf: Buffer)
    {
        this._lastError = err;
        if (err)
            setImmediate(this.ResponseHandler.bind(this), null);
        else
        {
            let rc: TPM_RC = respBuf.readUInt32BE(6);
            if (rc == TPM_RC.RETRY)
                this.device.dispatchCommand(this.CmdBuf.buffer, this.InterimResponseHandler.bind(this));
            else
                setImmediate(this.ResponseHandler.bind(this), new TpmBuffer(respBuf));
        }
    }

    protected dispatchCommand(cmdBuf: TpmBuffer, responseHandler: (resp: TpmBuffer) => void)
    {
        // Fill in command buffer size in the command header
        cmdBuf.buffer.writeUInt32BE(cmdBuf.length, 2);
        this.ResponseHandler = responseHandler;
        this.CmdBuf = cmdBuf;
        this.device.dispatchCommand(cmdBuf.buffer, this.InterimResponseHandler.bind(this));
    }

    protected generateErrorResponse(rc: TPM_RC): TpmBuffer
    {
        let respBuf = new TpmBuffer(10);
        respBuf.toTpm(TPM_ST.NO_SESSIONS, 2);
        respBuf.toTpm(10, 4);
        respBuf.toTpm(rc, 4);
        return respBuf;
    }

    protected generateError(cmdCode: TPM_CC, respCode: TPM_RC, errMsg: string, noThrow: boolean): TpmError
    {
        let err = new TpmError(respCode, TPM_CC[cmdCode], errMsg);
        if (this.exceptionsEnabled && !noThrow)
            throw err;
        return err;
    }

    protected getCmdError(cmd: string): TpmError
    {
        let rc = this.lastResponseCode;
        return rc == TPM_RC.SUCCESS ? null : new TpmError(rc, cmd,
                        "TPM command {" + cmd + "}" + "failed with response code {" + rc + "}");
    }

    // Returns pair [response parameters size, error if any]
    protected processResponse(cmdCode: TPM_CC, respBuf: TpmBuffer): number
    {
        let noThrow = this.errorsAllowed;
        this.errorsAllowed = !this.exceptionsEnabled;

        if (respBuf.length < 10)
        {
            this._lastError = new TpmError(TPM_RC.TSS_RESP_BUF_TOO_SHORT, TPM_CC[cmdCode], 'Response buffer is too short: ' + respBuf.length);
            return 0;
        }

        if (respBuf.curPos != 0)
            throw new Error("Response buffer reading position is not properly initialized!");

        let tag: TPM_ST = respBuf.fromTpm(2);
        let respSize: number = respBuf.fromTpm(4);
        let rc: TPM_RC = respBuf.fromTpm(4);

        this._lastResponseCode = TpmBase.cleanResponseCode(rc);

        if (rc == TPM_RC.SUCCESS && tag != this.cmdTag ||
            rc != TPM_RC.SUCCESS && tag != TPM_ST.NO_SESSIONS)
        {
            this._lastError = new TpmError(TPM_RC.TSS_RESP_BUF_INVALID_SESSION_TAG, TPM_CC[cmdCode], 'Invalid session tag in the response buffer');
            return 0;
        }

        if (this._lastResponseCode != TPM_RC.SUCCESS)
        {
            this._lastError = new TpmError(this._lastResponseCode, TPM_CC[cmdCode]);
            if (!noThrow)
                throw this._lastError;
            return 0;
        }

        let retHandle: TPM_HANDLE = null;
        if (cmdCode == TPM_CC.CreatePrimary
            || cmdCode == TPM_CC.Load
            || cmdCode == TPM_CC.HMAC_Start
            || cmdCode == TPM_CC.ContextLoad
            || cmdCode == TPM_CC.LoadExternal
            || cmdCode == TPM_CC.StartAuthSession
            || cmdCode == TPM_CC.HashSequenceStart
            || cmdCode == TPM_CC.CreateLoaded)
        {
            // Response buffer contains a handle returned by the TPM
            retHandle = respBuf.createFromTpm(TPM_HANDLE);
            //assert(retHandle.handle != 0 && retHandle.handle != TPM_RH.UNASSIGNED);
        }

        // If a response session is present, response buffer contains a field specifying the size of response parameters
        let respParamsSize: number = respBuf.length - respBuf.curPos;
        if (tag == TPM_ST.SESSIONS)
            respParamsSize = respBuf.fromTpm(4);

        if (retHandle != null)
        {
            // A trick to simplify code gen for returned handles handling
            respBuf.curPos = respBuf.curPos - 4;
            retHandle.toTpm(respBuf);
            respBuf.curPos = respBuf.curPos - 4;
            respParamsSize += 4;
        }

        return respParamsSize;
    } // processResponse()

}; // class TpmBase
