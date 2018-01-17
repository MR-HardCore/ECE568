 /*
 * Trivial malloc() implementation
 *
 * Inspired by K&R2 malloc() and Doug Lea malloc().
 */

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <assert.h>
#include <stdint.h>

/*
 * the chunk header
 */
typedef uint64_t ALIGN;

typedef union CHUNK_TAG
{
  struct
    {
      uint32_t l;       /* leftward chunk */
      uint32_t r;       /* rightward chunk + free bit (see below) */
    } s;
  ALIGN x;
} CHUNK;

/*
 * we store the freebit -- 1 if the chunk is free, 0 if it is busy --
 * in the low-order bit of the chunk's r pointer.
 */

#define SET_FREEBIT(chunk) ( (chunk)->s.r |= 0x1 )
#define CLR_FREEBIT(chunk) ( (chunk)->s.r &= ~0x1 )
#define GET_FREEBIT(chunk) ( (chunk)->s.r & 0x1 )

/* it's only safe to operate on chunk->s.r if we know freebit
 * is unset; otherwise, we use ... */
#define RIGHT(chunk) ((CHUNK *)(~0x1 & (uint64_t)(chunk)->s.r))

/*
 * chunk size is implicit from l-r
 */
#define CHUNKSIZE(chunk) ((uint64_t)RIGHT((chunk)) - (uint64_t)(chunk))

/*
 * back or forward chunk header
 */
#define TOCHUNK(vp) (-1 + (CHUNK *)(vp))
#define FROMCHUNK(chunk) ((void *)(1 + (chunk)))

/* for demo purposes, a static arena is good enough. */
#define ARENA_CHUNKS (65536/sizeof(CHUNK))
static unsigned int dummy[2700000];
static CHUNK arena[ARENA_CHUNKS];

static CHUNK *bot = NULL;       /* all free space, initially */
static CHUNK *top = NULL;       /* delimiter chunk for top of arena */

static void init(void)
{
  bot = &arena[0]; top = &arena[ARENA_CHUNKS-1];
  bot->s.l = (uint32_t)(uint64_t)NULL; bot->s.r = (uint32_t)(uint64_t)top;
  top->s.l = (uint32_t)(uint64_t)bot;  top->s.r = (uint32_t)(uint64_t)NULL;
  SET_FREEBIT(bot); CLR_FREEBIT(top);

  void * vp = (void *) &arena;
  uint64_t pageAlign = (uint64_t)vp % getpagesize();
  vp -= pageAlign;
  int rc;
  rc = mprotect(vp, (ARENA_CHUNKS * sizeof(CHUNK)) + pageAlign, (PROT_READ|PROT_WRITE|PROT_EXEC));
  assert ( rc == 0 );
}

void *tmalloc(unsigned nbytes)
{
  CHUNK *p;
  uint64_t size;

  if (bot == NULL)
    init();

  size = sizeof(CHUNK) * ((nbytes+sizeof(CHUNK)-1)/sizeof(CHUNK) + 1);

  for (p = bot; p != NULL; p = RIGHT(p))
    if (GET_FREEBIT(p) && CHUNKSIZE(p) >= size)
      break;
  if (p == NULL)
    return NULL;

  CLR_FREEBIT(p);
  if (CHUNKSIZE(p) > size)      /* create a remainder chunk */
    {
      CHUNK *q, *pr;
      q = (CHUNK *)(size + (char *)p);
      pr = (CHUNK *)(uint64_t)p->s.r;
      q->s.l = (uint32_t)(uint64_t)p; q->s.r = (uint32_t)(uint64_t)pr;
      p->s.r = (uint32_t)(uint64_t)q; pr->s.l = (uint32_t)(uint64_t)q;
      SET_FREEBIT(q);
    }
  return FROMCHUNK(p);
}

void tfree(void *vp)
{
  CHUNK *p, *q;

  if (vp == NULL)
    return;

  p = TOCHUNK(vp);
  CLR_FREEBIT(p);
  q = (CHUNK *)(uint64_t)p->s.l;
 if (q) {
  }
  if (q != NULL && GET_FREEBIT(q)) /* try to consolidate leftward */
    {
      CLR_FREEBIT(q);
      q->s.r      = p->s.r;
      ((CHUNK *)(uint64_t)(p->s.r))->s.l = (uint32_t)(uint64_t)q;
      SET_FREEBIT(q);
      p = q;
    }
  q = RIGHT(p);
  if (q != NULL && GET_FREEBIT(q)) /* try to consolidate rightward */
    {
      CLR_FREEBIT(q);
      p->s.r      = q->s.r;
      ((CHUNK *)(uint64_t)q->s.r)->s.l = (uint32_t)(uint64_t)p;
      SET_FREEBIT(q);
    }
  SET_FREEBIT(p);
}

void *trealloc(void *vp, unsigned newbytes)
{
  void *newp = NULL;

  /* behavior on corner cases conforms to SUSv2 */
  if (vp == NULL)
    return tmalloc(newbytes);

  if (newbytes != 0)
    {
      CHUNK *oldchunk;
      uint64_t bytes;

      if ( (newp = tmalloc(newbytes)) == NULL)
        return NULL;
      oldchunk = TOCHUNK(vp);
      bytes = CHUNKSIZE(oldchunk) - sizeof(CHUNK);
      if (bytes > newbytes)
        bytes = newbytes;
      memcpy(newp, vp, bytes);
    }

  tfree(vp);
  return newp;
}

void *tcalloc(unsigned nelem, unsigned elsize)
{
  void *vp;
  unsigned nbytes;

  nbytes = nelem * elsize;
  if ( (vp = tmalloc(nbytes)) == NULL)
    return NULL;
  memset(vp, '\0', nbytes);
  return vp;
}
