#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/fs.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/vmalloc.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>

#define RAMBLK_NAME              "ramblk"
#define RAMBLK_MAX_DEVICE        2
#define RAMBLK_MAX_PARTITIONS    4

#define RAMBLK_SECTOR_SIZE       512
#define RAMBLK_SECTORS           16
#define RAMBLK_HEADS             4
#define RAMBLK_CYLINDERS         256

#define RAMBLK_SECTOR_TOTAL      (RAMBLK_SECTORS * RAMBLK_HEADS * RAMBLK_CYLINDERS)
#define RAMBLK_SIZE              (RAMBLK_SECTOR_SIZE * RAMBLK_SECTOR_TOTAL) //8MB

struct ramblk_dev {
	unsigned char *data;
	struct request_queue *queue;
	struct gendisk  *gd;
};

static void *sdisk[RAMBLK_MAX_DEVICE] = {NULL,};
static struct ramblk_dev *rdev[RAMBLK_MAX_DEVICE] = {NULL,};

static dev_t ramblk_major;

static int ramblk_space_init(void)
{
	int i;
	int err = 0;

	for (i = 0; i < RAMBLK_MAX_DEVICE; i++) {
		sdisk[i] = vmalloc(RAMBLK_SIZE);
		if (!sdisk[i]) {
			pr_err("vmalloc failed!");
			err = -ENOMEM;
			goto err_out;
		}
		memset(sdisk[i], 0, RAMBLK_SIZE);
		pr_info("Addr:ramblk[%d] = %p\n", i, sdisk[i]);
	}

	return err;

err_out:
	for (i = 0; i < RAMBLK_MAX_DEVICE; i++) {
		if (sdisk[i])
			vfree(sdisk[i]);
	}

	return err;
}

static void ramblk_space_clean(void)
{
	int i;

	for (i = 0; i < RAMBLK_MAX_DEVICE; i++)
		vfree(sdisk[i]);
}

static int ramblk_open(struct block_device *bdev, fmode_t mode)
{
	return 0;
}

static void ramblk_release(struct gendisk *gd, fmode_t mode)
{

}

static int ramblk_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd, unsigned long arg)
{
	int err;
	struct hd_geometry geo;

	switch (cmd) {
	case HDIO_GETGEO:
		err = !access_ok(VERIFY_WRITE, arg, sizeof(geo));
		if (err)
			return -EFAULT;

		geo.cylinders = RAMBLK_CYLINDERS;
		geo.heads = RAMBLK_HEADS;
		geo.sectors = RAMBLK_SECTORS;
		geo.start = get_start_sect(bdev);
		if (copy_to_user((void *)arg, &geo, sizeof(geo)))
			return -EFAULT;

		return 0;
	}

	return -ENOTTY;
}

static const struct block_device_operations ramblk_fops = {
	.owner = THIS_MODULE,
	.open = ramblk_open,
	.release = ramblk_release,
	.ioctl = ramblk_ioctl,
};

static blk_qc_t ramblk_make_request(struct request_queue *q, struct bio *bio)
{
	void *bdata, *mbuf;
	struct bio_vec bvec;
	struct bvec_iter iter;
	struct gendisk *gd;
	int err = 0;

	struct block_device *bdev = bio->bi_bdev;
	struct ramblk_dev *pdev = bdev->bd_disk->private_data;

	gd = pdev->gd;

	if (bio_end_sector(bio) > get_capacity(gd)) {
		err = -EINVAL;
		goto out;
	}

	bdata = pdev->data + (bio->bi_iter.bi_sector * RAMBLK_SECTOR_SIZE);

	bio_for_each_segment(bvec, bio, iter) {
		mbuf = kmap_atomic(bvec.bv_page) + bvec.bv_offset;
		switch (bio_data_dir(bio)) {
		case READ:
			memcpy(mbuf, bdata, bvec.bv_len);
			flush_dcache_page(bvec.bv_page);
			break;
		case WRITE:
			flush_dcache_page(bvec.bv_page);
			memcpy(bdata, mbuf, bvec.bv_len);
			break;
		default:
			kunmap_atomic(mbuf);
			goto out;
		}

		kunmap_atomic(mbuf);
		bdata += bvec.bv_len;
	}
out:
	if (err)
		bio->bi_error = err;

	bio_endio(bio);

	return BLK_QC_T_NONE;
}

static int alloc_ramdev(void)
{
	int i, err = 0;

	for (i = 0; i < RAMBLK_MAX_DEVICE; i++) {
		rdev[i] = kzalloc(sizeof(struct ramblk_dev), GFP_KERNEL);
		if (!rdev[i]) {
			err = -ENOMEM;
			goto err_out;
		}
	}

	return err;

err_out:
	for (i = 0; i < RAMBLK_MAX_DEVICE; i++)
		kfree(rdev[i]);

	return err;
}

static void clean_ramdev(void)
{
	int i;

	for (i = 0; i < RAMBLK_MAX_DEVICE; i++)
		kfree(rdev[i]);

}

static int __init ramblk_init(void)
{
	int i, err = 0;

	err = ramblk_space_init();
	if (err)
		return err;

	alloc_ramdev();

	ramblk_major = register_blkdev(0, RAMBLK_NAME);

	for (i = 0; i < RAMBLK_MAX_DEVICE; i++) {
		rdev[i]->data = sdisk[i];
		rdev[i]->queue = blk_alloc_queue(GFP_KERNEL);
		rdev[i]->gd = alloc_disk(RAMBLK_MAX_PARTITIONS);
		blk_queue_make_request(rdev[i]->queue, ramblk_make_request);
		blk_queue_bounce_limit(rdev[i]->queue, BLK_BOUNCE_ANY);
		queue_flag_set_unlocked(QUEUE_FLAG_NONROT, rdev[i]->queue);
		rdev[i]->gd->major = ramblk_major;
		rdev[i]->gd->first_minor = i * RAMBLK_MAX_PARTITIONS;
		rdev[i]->gd->fops = &ramblk_fops;
		rdev[i]->gd->queue = rdev[i]->queue;
		rdev[i]->gd->private_data = rdev[i];
		sprintf(rdev[i]->gd->disk_name, "ramblk%c", 'a'+i);
		rdev[i]->gd->flags |= GENHD_FL_SUPPRESS_PARTITION_INFO;
		set_capacity(rdev[i]->gd, RAMBLK_SECTOR_TOTAL);
		add_disk(rdev[i]->gd);
	}
	return err;
}

static void __exit ramblk_exit(void)
{
	int i;

	for (i = 0; i < RAMBLK_MAX_DEVICE; i++) {
		del_gendisk(rdev[i]->gd);
		put_disk(rdev[i]->gd);
		blk_cleanup_queue(rdev[i]->queue);
	}

	clean_ramdev();
	ramblk_space_clean();
	unregister_blkdev(ramblk_major, RAMBLK_NAME);
}

module_init(ramblk_init);
module_exit(ramblk_exit);

MODULE_AUTHOR("dennis chen @github.com/dennisarm");
MODULE_DESCRIPTION("A simple implementation of bio-based ram disk");
MODULE_LICENSE("GPL");
